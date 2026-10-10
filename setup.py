"""
PAW - Phishing Attribution Workbench
Setup configuration for package installation
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_file(filename):
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, filename), encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements(filename):
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, filename), encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='paw',
    version='2.0.0',
    description='Phishing Attribution Workbench - Advanced Email Forensics Tool',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    author='PAW Development Team',
    author_email='security@example.com',
    url='https://github.com/yourusername/paw',
    license='MIT',

    # Package configuration
    packages=find_packages(exclude=['tests', 'tests.*', 'SAVE', 'SAVE.*']),
    include_package_data=True,
    python_requires='>=3.11',

    # Dependencies
    install_requires=read_requirements('requirements.txt'),

    # Optional dependencies
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.7.0',
            'flake8>=6.1.0',
            'mypy>=1.5.0',
            'isort>=5.12.0',
        ],
        'ml': [
            'scikit-learn>=1.3.0',
            'numpy>=1.24.0',
            'pandas>=2.0.0',
        ],
        'docs': [
            'sphinx>=7.1.0',
            'sphinx-rtd-theme>=1.3.0',
        ],
    },

    # Entry points
    entry_points={
        'console_scripts': [
            'paw=paw.__main__:main',
            'paw-analyze=paw.core.trace:main',
            'paw-detonate=paw.detonate.runner:main',
            'paw-canary=paw.canary.server:main',
        ],
    },

    # Package data
    package_data={
        'paw': [
            'i18n/*.json',
            'templates/*.txt',
        ],
    },

    # Classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
    ],

    # Keywords
    keywords='phishing email forensics attribution security cybersecurity',

    # Project URLs
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/paw/issues',
        'Source': 'https://github.com/yourusername/paw',
        'Documentation': 'https://paw.readthedocs.io/',
    },

    # Zip safe
    zip_safe=False,
)
