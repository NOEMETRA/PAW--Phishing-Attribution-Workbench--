# paw/sentinel/geographic_reports.py
"""
Automated Geographic Reports for PAW Intelligence.
Generates maps and statistics showing attacker locations and victim distributions.
"""

import json
import os
import time
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd


class GeographicReporter:
    """Generate geographic reports for victim intelligence analysis."""

    def __init__(self, db_connection=None):
        self.db = db_connection
        self.reports_dir = "reports/geographic"
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_geographic_report(self, case_id: str = None, min_confidence: float = 0.0,
                                   exclude_countries: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate comprehensive geographic report for victims.

        Args:
            case_id: optional case identifier to limit data
            min_confidence: minimum interaction confidence to include
            exclude_countries: optional list of country names (case-insensitive)
                to exclude from the generated report (useful for sanitizing
                distributions without modifying case evidence files).
        """
        print(f"🗺️  Generando report geografico per case_id: {case_id or 'TUTTI'}")

        # Get victim data
        victims = self._get_victim_data(case_id, min_confidence)

        if not victims:
            return {
                'status': 'no_data',
                'message': 'Nessun dato vittima disponibile per il report',
                'case_id': case_id,
                'total_victims': 0
            }

        # Analyze geographic distribution
        geo_stats = self._analyze_geographic_distribution(victims)

        # Generate visualizations
        visualizations = self._generate_visualizations(geo_stats)

        # Create report
        report = {
            'status': 'success',
            'generated_at': time.time(),
            'case_id': case_id,
            'total_victims': len(victims),
            'min_confidence': min_confidence,
            'geographic_stats': geo_stats,
            'visualizations': visualizations,
            'summary': self._generate_summary(geo_stats)
        }

        # Save report
        self._save_report(report, case_id)

        return report


    def _get_victim_data(self, case_id: str = None, min_confidence: float = 0.0) -> List[Dict]:
        """Retrieve victim data from the database."""
        query = "SELECT * FROM victims WHERE interaction_confidence >= ?"
        params = [min_confidence]

        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)

        cursor = self.db.execute(query, params)
        rows = cursor.fetchall()

        victims = []
        for row in rows:
            victim = dict(row)
            # Parse geolocation JSON field
            geo_data = victim.get('geolocation_data')
            if geo_data:
                try:
                    victim['geolocation_data'] = json.loads(geo_data)
                except json.JSONDecodeError:
                    victim['geolocation_data'] = {}
            else:
                victim['geolocation_data'] = {}
            victims.append(victim)

        return victims

    def _analyze_geographic_distribution(self, victims: List[Dict]) -> Dict[str, Any]:
        """Analyze geographic distribution of victims."""
        countries = Counter()
        regions = Counter()
        cities = Counter()
        interaction_types = defaultdict(lambda: defaultdict(int))

        attacker_countries = []
        victim_countries = []

        for victim in victims:
            geo = victim.get('geolocation_data', {})
            interaction_type = victim.get('interaction_type', 'unknown')

            country = geo.get('country', 'Unknown')
            region = geo.get('region', 'Unknown')
            city = geo.get('city', 'Unknown')

            countries[country] += 1
            regions[f"{country} - {region}"] += 1
            cities[f"{country} - {city}"] += 1

            interaction_types[interaction_type][country] += 1

            # Separate attackers and victims
            if interaction_type in ['attacker', 'suspicious']:
                attacker_countries.append(country)
            else:
                victim_countries.append(country)

        return {
            'countries': dict(countries.most_common()),
            'regions': dict(regions.most_common(10)),
            'cities': dict(cities.most_common(10)),
            'interaction_types': dict(interaction_types),
            'attacker_countries': list(set(attacker_countries)),
            'victim_countries': list(set(victim_countries)),
            'total_countries': len(countries),
            'top_attacker_country': max(attacker_countries, key=attacker_countries.count) if attacker_countries else None,
            'coordinates': self._extract_coordinates(victims)
        }

    def _extract_coordinates(self, victims: List[Dict]) -> List[Dict]:
        """Extract coordinates for mapping."""
        coordinates = []

        for victim in victims:
            geo = victim.get('geolocation_data', {})
            lat = geo.get('lat')
            lon = geo.get('lon')

            if lat and lon:
                coordinates.append({
                    'lat': lat,
                    'lon': lon,
                    'country': geo.get('country', 'Unknown'),
                    'city': geo.get('city', 'Unknown'),
                    'interaction_type': victim.get('interaction_type', 'unknown'),
                    'ip': victim.get('victim_ip', 'Unknown')
                })

        return coordinates

    def _generate_visualizations(self, geo_stats: Dict) -> Dict[str, str]:
        """Generate geographic visualizations."""
        visualizations = {}

        try:
            # Country distribution chart
            countries_df = pd.DataFrame(list(geo_stats['countries'].items()),
                                      columns=['Country', 'Count'])

            fig_countries = px.bar(countries_df, x='Country', y='Count',
                                 title='Distribuzione Vittime per Paese',
                                 color='Count',
                                 color_continuous_scale='Reds')
            visualizations['countries_chart'] = fig_countries.to_html(full_html=False)

            # World map with victim locations
            if geo_stats['coordinates']:
                coords_df = pd.DataFrame(geo_stats['coordinates'])

                # Color by interaction type
                color_map = {
                    'victim': 'green',
                    'attacker': 'red',
                    'suspicious': 'orange',
                    'unknown': 'gray'
                }

                coords_df['color'] = coords_df['interaction_type'].map(color_map)

                fig_map = px.scatter_geo(coords_df,
                                       lat='lat',
                                       lon='lon',
                                       color='interaction_type',
                                       hover_name='city',
                                       hover_data=['ip', 'country'],
                                       title='Mappa Globale Vittime e Attaccanti',
                                       projection='natural earth')

                visualizations['world_map'] = fig_map.to_html(full_html=False)

            # Interaction types by country
            if geo_stats['interaction_types']:
                interaction_data = []
                for int_type, countries in geo_stats['interaction_types'].items():
                    for country, count in countries.items():
                        interaction_data.append({
                            'Interaction_Type': int_type,
                            'Country': country,
                            'Count': count
                        })

                if interaction_data:
                    int_df = pd.DataFrame(interaction_data)
                    fig_interaction = px.bar(int_df,
                                           x='Country',
                                           y='Count',
                                           color='Interaction_Type',
                                           title='Tipi Interazione per Paese',
                                           barmode='stack')
                    visualizations['interaction_chart'] = fig_interaction.to_html(full_html=False)

        except Exception as e:
            print(f"⚠️  Errore generazione visualizzazioni: {e}")
            visualizations['error'] = str(e)

        return visualizations

    def _generate_summary(self, geo_stats: Dict) -> Dict[str, Any]:
        """Generate human-readable summary."""
        countries = geo_stats['countries']
        attacker_countries = geo_stats['attacker_countries']
        victim_countries = geo_stats['victim_countries']

        summary = {
            'total_countries': geo_stats['total_countries'],
            'top_countries': list(countries.keys())[:5],
            'attacker_countries': attacker_countries,
            'victim_countries': victim_countries,
            'risk_assessment': self._assess_geographic_risk(geo_stats)
        }

        return summary

    def _assess_geographic_risk(self, geo_stats: Dict) -> Dict[str, Any]:
        """Assess geographic risk based on distribution."""
        attacker_countries = geo_stats['attacker_countries']
        total_countries = geo_stats['total_countries']

        risk_level = "LOW"
        risk_factors = []

        # High concentration of attackers in few countries
        if len(attacker_countries) <= 2 and total_countries > 5:
            risk_level = "HIGH"
            risk_factors.append("Concentrazione elevata di attaccanti in pochi paesi")

        # Many attacker countries
        elif len(attacker_countries) > total_countries * 0.5:
            risk_level = "MEDIUM"
            risk_factors.append("Attaccanti distribuiti in molti paesi")

        # Normal distribution
        else:
            risk_factors.append("Distribuzione normale di attaccanti")

        return {
            'level': risk_level,
            'factors': risk_factors,
            'attacker_country_ratio': len(attacker_countries) / max(total_countries, 1)
        }

    def _save_report(self, report: Dict, case_id: str = None):
        """Save report to file."""
        try:
            filename = f"geographic_report_{case_id or 'all'}_{int(time.time())}.json"
            filepath = os.path.join(self.reports_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"💾 Report salvato: {filepath}")

            # Generate HTML report
            self._generate_html_report(report, case_id)

        except Exception as e:
            print(f"❌ Errore salvataggio report: {e}")

    def _generate_html_report(self, report: Dict, case_id: str = None):
        """Generate HTML version of the report."""
        try:
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Report Geografico PAW - {case_id or 'Tutti i Casi'}</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #e8f4f8; padding: 15px; border-radius: 5px; flex: 1; }}
        .visualization {{ margin: 20px 0; }}
        .risk-high {{ color: #d9534f; }}
        .risk-medium {{ color: #f0ad4e; }}
        .risk-low {{ color: #5cb85c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🗺️ Report Geografico PAW</h1>
        <p><strong>Caso:</strong> {case_id or 'Tutti i Casi'}</p>
        <p><strong>Generato:</strong> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report['generated_at']))}</p>
        <p><strong>Totale Vittime:</strong> {report['total_victims']}</p>
    </div>

    <div class="stats">
        <div class="stat-box">
            <h3>📊 Statistiche Geografiche</h3>
            <p><strong>Paesi Totali:</strong> {report['summary']['total_countries']}</p>
            <p><strong>Paesi Attaccanti:</strong> {len(report['summary']['attacker_countries'])}</p>
            <p><strong>Paesi Vittime:</strong> {len(report['summary']['victim_countries'])}</p>
        </div>
        <div class="stat-box">
            <h3>🚨 Valutazione Rischio</h3>
            <p><strong>Livello:</strong>
                <span class="risk-{report['summary']['risk_assessment']['level'].lower()}">
                    {report['summary']['risk_assessment']['level']}
                </span>
            </p>
            <p><strong>Fattori:</strong> {', '.join(report['summary']['risk_assessment']['factors'])}</p>
        </div>
    </div>

    <h2>🌍 Distribuzione per Paese</h2>
    <ul>
"""

            for country, count in list(report['geographic_stats']['countries'].items())[:10]:
                html_content += f"        <li><strong>{country}:</strong> {count} interazioni</li>\n"

            html_content += """
    </ul>

    <h2>🎯 Attaccanti per Paese</h2>
    <ul>
"""

            for country in report['summary']['attacker_countries']:
                html_content += f"        <li>{country}</li>\n"

            html_content += """
    </ul>

    <h2>📈 Visualizzazioni</h2>
"""

            if 'world_map' in report['visualizations']:
                html_content += f"""
    <div class="visualization">
        <h3>Mappa Globale</h3>
        {report['visualizations']['world_map']}
    </div>
"""

            if 'countries_chart' in report['visualizations']:
                html_content += f"""
    <div class="visualization">
        <h3>Distribuzione per Paese</h3>
        {report['visualizations']['countries_chart']}
    </div>
"""

            html_content += """
</body>
</html>
"""

            html_filename = f"geographic_report_{case_id or 'all'}_{int(time.time())}.html"
            html_filepath = os.path.join(self.reports_dir, html_filename)

            with open(html_filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"📄 Report HTML salvato: {html_filepath}")

        except Exception as e:
            print(f"❌ Errore generazione HTML: {e}")


def generate_geographic_report_cli(case_id: str = None, min_confidence: float = 0.0, output_format: str = 'both'):
    """CLI function to generate geographic reports."""
    try:
        reporter = GeographicReporter()

        print(f"🔍 Generando report geografico per case_id: {case_id or 'TUTTI'}")
        print(f"📊 Confidenza minima: {min_confidence}")
        print(f"📁 Formato output: {output_format}")

        report = reporter.generate_geographic_report(case_id, min_confidence)

        if report['status'] == 'success':
            print("✅ Report generato con successo!")
            print(f"📊 Vittime analizzate: {report['total_victims']}")
            print(f"🌍 Paesi coinvolti: {report['summary']['total_countries']}")
            print(f"🚨 Paesi attaccanti: {len(report['summary']['attacker_countries'])}")
            print(f"⚠️  Livello rischio: {report['summary']['risk_assessment']['level']}")

            if report['summary']['attacker_countries']:
                print(f"🎯 Attaccanti principali: {', '.join(report['summary']['attacker_countries'][:3])}")
        else:
            print(f"❌ {report['message']}")

    except Exception as e:
        print(f"❌ Errore generazione report: {e}")


if __name__ == "__main__":
    # Test the geographic reporter
    print("🗺️  Test Report Geografico PAW")
    print("=" * 40)

    reporter = GeographicReporter()
    report = reporter.generate_geographic_report()

    print("\n📊 Risultati Test:")
    print(f"Status: {report['status']}")
    if report['status'] == 'success':
        print(f"Vittime: {report['total_victims']}")
        print(f"Paesi: {report['summary']['total_countries']}")
        print(f"Rischio: {report['summary']['risk_assessment']['level']}")
        print("✅ Report generato con successo!")
    else:
        print(f"Errore: {report.get('message', 'Sconosciuto')}")