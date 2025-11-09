// to prevent infinite loops as any interaction with the OneTrust script runs the OptanonWrapper Callback again
let hasRunOptanonWrapper = false;
let attQueryParamResolved = false;

function OptanonWrapper() {
  if (!hasRunOptanonWrapper) {
    resolveAttParamIfNeeded(attQueryParamResolved);
    setDefaultGtagConsent();
    if (adobe && adobe.OptInCategories) {
      adobeProductsMappingTrigger();
    }
    hasRunOptanonWrapper = true;
  }
}

function resolveAttParamIfNeeded(attQueryParamResolved) {
  if (!attQueryParamResolved) {
    const attParamValue = getQueryParameterOW('att');
    handleAttParamChange(attParamValue, attQueryParamResolved);
  }
}

const findConsentDataLayerEvent = (dataLayer, eventType) => {
  return dataLayer?.find(item => item[0] === 'consent' && item[1] === eventType);
};

const setDefaultGtagConsent = () => {
  const isOptanonGroupsUpdated = findConsentDataLayerEvent(dataLayer, 'update');
  const hasConsentDefaultLoaded = findConsentDataLayerEvent(dataLayer, 'default');

  if (typeof gtag === 'function' && !isOptanonGroupsUpdated && !hasConsentDefaultLoaded) {
    gtag('consent', 'default', {
      ad_storage: 'denied',
      ad_user_data: 'denied',
      ad_personalization: 'denied',
      analytics_storage: 'denied',
      wait_for_update: 500,
    });
  }
};

const handleAttParamChange = (attParamValue, attQueryParamResolved) => {
  if (!attQueryParamResolved) {
    clearQueryParams();
    attQueryParamResolved = true;
    handleAttParamValue(attParamValue);
  }
};

const handleAttParamValue = attParamValue => {
  executeIfOneTrustAvailable(() => {
    if (attParamValue === '0') {
      OneTrust.RejectAll();
      rejectAllAdobeSolutionsOW();
    } else if (attParamValue === '1') {
      OneTrust.AllowAll();
      approveAllAdobeSolutionsOW();
    }
  });
};

const clearQueryParams = () => {
  const currentUrl = new URL(window.location.href);
  currentUrl.searchParams.delete('att');
  currentUrl.searchParams.delete('hidebanner');
  window.history.replaceState(null, null, currentUrl.toString());
};

const getQueryParameterOW = name => {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
};

const handleAdobeOptInOW = action => {
  if (typeof adobe.optIn !== 'undefined') {
    const adobeProductsToApprove = ['aam', 'aa', 'campaign', 'ecid', 'target'];
    adobe.optIn[action](adobeProductsToApprove);
    adobe.optIn.complete();
  }
};

const rejectAllAdobeSolutionsOW = () => handleAdobeOptInOW('deny');
const approveAllAdobeSolutionsOW = () => handleAdobeOptInOW('approve');

const adobeProductOnetrustCategorisationMapping = () => {
  // OptanonActiveGroup string values
  const [PERFORMANCE_COOKIES_CONSENTED, FUNCTIONAL_COOKIES_CONSENTED, TARGETING_COOKIES_CONSENTED] = [
    'C0002',
    'C0003',
    'C0004',
  ];

  const isPerformanceConsent = OptanonActiveGroups.includes(PERFORMANCE_COOKIES_CONSENTED);
  const isFunctionalConsent = OptanonActiveGroups.includes(FUNCTIONAL_COOKIES_CONSENTED);
  const isTargetingConsent = OptanonActiveGroups.includes(TARGETING_COOKIES_CONSENTED);

  const allTrue = (...arr) => arr.every(val => val === true);

  const {
    AAM: adobe_audience_manager,
    ANALYTICS: adobe_analytics,
    CAMPAIGN: adobe_campaign,
    ECID: adobe_cloud_id,
    TARGET: adobe_target,
  } = adobe.OptInCategories;

  const adobeProductConsentCategories = {
    functional: [adobe_cloud_id, adobe_audience_manager, adobe_target, adobe_campaign],
    performance: [adobe_analytics],
  };

  const { functional, performance } = adobeProductConsentCategories;

  const combineProducts = (...categories) => {
    const combinedCategories = categories.flat();
    return [...combinedCategories];
  };

  // no targeting currently used
  const functionalAndPerformanceAdobeProducts = combineProducts(functional, performance);
  const functionalAndTargetingAdobeProducts = [...functional];
  const targetingAndPerformanceAdobeProducts = [...performance];

  if (typeof adobe.optIn !== 'undefined') {
    const {
      optIn: { approve, denyAll, complete },
    } = adobe;

    denyAll();
    complete();

    const consentSettings = {
      isFullConsent: {
        condition: allTrue(isPerformanceConsent, isFunctionalConsent, isTargetingConsent),
        action: () => {
          approve([...functional, ...performance]);
        },
      },
      isFunctionalConsentOnly: {
        condition: allTrue(isFunctionalConsent, !isTargetingConsent, !isPerformanceConsent),
        action: () => {
          approve(functional);
        },
      },
      isTargetingConsentOnly: {
        condition: allTrue(isTargetingConsent, !isFunctionalConsent, !isPerformanceConsent),
        action: () => {
          // no adobe targeting options at present
          return false;
        },
      },
      isPerformanceConsentOnly: {
        condition: allTrue(isPerformanceConsent, !isFunctionalConsent, !isTargetingConsent),
        action: () => {
          approve(performance);
        },
      },
      isFunctionalAndPerformanceConsent: {
        condition: allTrue(isFunctionalConsent, isPerformanceConsent, !isTargetingConsent),
        action: () => {
          approve(functionalAndPerformanceAdobeProducts);
        },
      },
      isFunctionalAndTargetingConsent: {
        condition: allTrue(isFunctionalConsent, isTargetingConsent, !isPerformanceConsent),
        action: () => {
          approve(functionalAndTargetingAdobeProducts);
        },
      },
      isPerformanceAndTargetingConsent: {
        condition: allTrue(isPerformanceConsent, isTargetingConsent, !isFunctionalConsent),
        action: () => {
          approve(targetingAndPerformanceAdobeProducts);
        },
      },
      isNoConsent: {
        condition: allTrue(!isPerformanceConsent, !isFunctionalConsent, !isTargetingConsent),
        action: () => {
          denyAll();
        },
      },
    };

    const consentChoice = Object.keys(consentSettings).find(key => consentSettings[key].condition);

    if (consentChoice && consentSettings[consentChoice]) {
      consentSettings[consentChoice].action();
    } else {
      console.error('No valid consent type found');
    }
    complete();
  }
};

const adobeProductsMappingTrigger = () => {
  executeIfOneTrustAvailable(() => {
    OneTrust?.OnConsentChanged(adobeProductOnetrustCategorisationMapping);
  });
};

const executeIfOneTrustAvailable = (callback, errorMessage = 'OneTrust is not available - OneTrust Script Error') => {
  if (!OneTrust) {
    console.warn(errorMessage);
  } else {
    callback();
  }
};
