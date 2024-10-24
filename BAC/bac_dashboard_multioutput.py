import dash
from dash import dcc, html, Input, Output, dash_table
from flask import Flask
from flask_cors import CORS
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import joblib
import base64
import io
import tempfile
import os

# Load model and preprocessor
model = joblib.load('models/multioutput_rf_model.pkl')
preprocessor = joblib.load('models/multioutput_preprocessor.pkl')

# Mitigation strategies
vulnerability_details = {
    'HAC': {
        'name': 'Horizontal Access Control',
        'possible_causes': ['Inadequate access control policies', 'Unrestricted resource access'],
        'mitigation_strategies': [
            'Implement role-based access controls.', 'Ensure users can only access relevant resources.',
            'Regularly audit access permissions.'
        ]
    },
    'VAC': {
        'name': 'Vertical Access Control',
        'possible_causes': ['Improper access level assignment', 'Lack of validation for access requests'],
        'mitigation_strategies': [
            'Enforce strict access controls.', 'Review user permissions regularly.', 
            'Implement multi-factor authentication.'
        ]
    },
    'IDOR': {
        'name': 'Insecure Direct Object References',
        'possible_causes': ['Predictable object identifiers', 'Improper validation of user inputs'],
        'mitigation_strategies': [
            'Use indirect references.', 'Sanitize user inputs.', 'Apply access controls at the app layer.'
        ]
    },
    'MFAC': {
        'name': 'Missing Function-Level Access Control',
        'possible_causes': ['Missing authorization checks', 'Improper function configuration'],
        'mitigation_strategies': [
            'Ensure all sensitive functions require proper authorization.',
            'Implement function-level access controls.', 'Review and update access policies regularly.'
        ]
    }
}

# Initialize Dash app with a Bootstrap theme
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CERULEAN], suppress_callback_exceptions=True)
CORS(app.server) #add cors
app.title = "BAC Detection Dashboard"  # Set the title of the page

# Layout of the app
app.layout = dbc.Container([
    # Banner at the top with the title
    dbc.Row([
        dbc.Col(html.Div([
            html.H1("Broken Access Control (BAC) Detection", className="text-center", style={'color': 'white', 'padding': '20px'}),
        ], style={'backgroundColor': '#004085', 'padding': '20px', 'border-radius': '10px'}), width=12),
    ], className="mb-4"),

    # Filter Dropdown
    dbc.Row([
        dbc.Col(dcc.Dropdown(
            id='filter-input',
            options=[
                {'label': 'All', 'value': 'All'},  # Add "All" option to the dropdown
                {'label': 'HAC', 'value': 'HAC'},
                {'label': 'VAC', 'value': 'VAC'},
                {'label': 'IDOR', 'value': 'IDOR'},
                {'label': 'MFAC', 'value': 'MFAC'},
                {'label': 'No Vulnerability', 'value': 'No Vulnerability'}
            ],
            multi=False,  
            placeholder="Filter by Access Type",
            className="mb-4",
            style={'font-size': '18px', 'border-color': '#004085'}
        ), width=12),
    ]),

    # File Upload Section
    dbc.Row([
        dbc.Col(dcc.Upload(
            id='upload-data',
            children=html.Div(['Drag and Drop or ', html.A('Select Files')]),
            style={
                'width': '100%', 'height': '60px', 'lineHeight': '60px',
                'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '10px',
                'textAlign': 'center', 'margin': '20px', 'color': '#004085', 'backgroundColor': '#f1f1f1'
            },
            multiple=False
        ), width=12),
    ]),

    # Charts Row
    dbc.Row([
        dbc.Col(dcc.Graph(id='pie-chart', style={'padding': '15px'}), width=6),
        dbc.Col(dcc.Graph(id='bar-chart', style={'padding': '15px'}), width=6)
    ]),

    # Timeline and Heatmap
    dbc.Row([
        dbc.Col(dcc.Graph(id='timeline', style={'padding': '15px'}), width=6),
        dbc.Col(dcc.Graph(id='heatmap', style={'padding': '15px'}), width=6)
    ]),

    # Time Range Insights Box
    dbc.Row([
        dbc.Col(html.Div(id='time-range-insights', className="mt-4", 
            style={
                'border': '2px solid #004085', 'border-radius': '8px', 'padding': '15px',
                'background-color': '#e9ecef', 'font-size': '18px', 'color': '#004085',
                'margin-bottom': '20px', 'font-weight': 'bold', 'text-align': 'center'
            }
        ), width=12)
    ]),

    # High Severity Alert section just below the time range insights
    dbc.Row([dbc.Col(html.Div(id='severity-alert', style={'margin-bottom': '20px'}), width=12)]),

    # Title before the table
    dbc.Row([
        dbc.Col(html.H3("Detections made", className="text-center", style={'color': '#004085', 'font-weight': 'bold', 'padding-top': '20px'}))
    ]),

    # Data Table for displaying records
    dbc.Row([
        dbc.Col(dash_table.DataTable(
            id='table-records',
            columns=[
                {'name': 'S.No', 'id': 'S.No'},
                {'name': 'Client IP', 'id': 'client_ip'},
                {'name': 'Detected Vulnerability', 'id': 'bac_vulnerability'},
                {'name': 'Severity', 'id': 'severity_level'},
                {'name': 'Priority', 'id': 'priority'}
            ],
            style_data_conditional=[
                {'if': {'filter_query': '{severity_level} > 7'}, 'backgroundColor': 'red', 'color': 'white'},
                {'if': {'filter_query': '{severity_level} >= 5 && {severity_level} <= 7'}, 'backgroundColor': 'orange', 'color': 'black'},
                {'if': {'filter_query': '{severity_level} >= 2 && {severity_level} < 5'}, 'backgroundColor': 'yellow', 'color': 'black'},
                {'if': {'filter_query': '{severity_level} eq 1'}, 'backgroundColor': 'green', 'color': 'white'}
            ],
            style_table={'overflowY': 'scroll', 'height': '300px', 'padding': '10px', 'border': '1px solid #004085', 'border-radius': '10px'},
            page_size=10
        ), width=12)
    ]),

    # Title for Severity and Priority distribution
    dbc.Row([
        dbc.Col(html.H3("Severity and priority distribution", className="text-center", style={'color': '#004085', 'font-weight': 'bold', 'padding-top': '20px'}))
    ]),

    # Vulnerability Insights Section - Histograms side by side
    dbc.Row([
        dbc.Col(dcc.Graph(id='severity-insights', style={'padding': '15px'}), width=6),
        dbc.Col(dcc.Graph(id='priority-insights', style={'padding': '15px'}), width=6),
    ]),

    # Beautiful Record Details Section
    dbc.Row([dbc.Col(html.Div(id='record-details', style={'padding': '15px', 'border-radius': '10px'}), width=12)]),

    # Centered Button Row for CSV Download
    dbc.Row([
        dbc.Col(html.Button('Download CSV', id='download-csv', className="btn btn-primary btn-lg", style={'width': '250px', 'background-color': '#007bff'}), width=3),
    ], className="mt-4 mb-4", justify="center"),

    # Hidden Download Components
    dcc.Download(id='csv-download')
], fluid=True, style={'background-color': '#f8f9fa', 'padding': '30px', 'border-radius': '15px'})  # Apply fluid container and background color

# Callback to sync pie chart click with dropdown
@app.callback(
    Output('filter-input', 'value'),
    [Input('pie-chart', 'clickData')]
)
def sync_pie_chart_click_with_dropdown(clickData):
    if clickData:
        clicked_vulnerability = clickData['points'][0]['label']
        return clicked_vulnerability  # Set the clicked vulnerability as the dropdown value
    return 'All'  # If no clickData, default to 'All'

# Combined callback for charts, tables, time range insights, and record details
@app.callback(
    [
        Output('pie-chart', 'figure'),
        Output('bar-chart', 'figure'),
        Output('timeline', 'figure'),
        Output('heatmap', 'figure'),
        Output('table-records', 'data'),
        Output('record-details', 'children'),
        Output('severity-alert', 'children'),
        Output('severity-insights', 'figure'),
        Output('priority-insights', 'figure'),
        Output('time-range-insights', 'children'),
        Output('csv-download', 'data')
    ],
    [
        Input('upload-data', 'contents'),
        Input('filter-input', 'value'),
        Input('table-records', 'active_cell'),
        Input('download-csv', 'n_clicks')
    ],
    prevent_initial_call=True  # Prevent callback from triggering on page load
)
def update_all_outputs(contents, filter_input, active_cell, csv_click):
    # Get the trigger context to see what caused the callback to fire
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update

    # Initialize default values for all outputs
    empty_fig = px.bar(title="No data")
    empty_table_data = []
    empty_details = html.Div("No record selected.", style={'font-size': '16px', 'color': '#6c757d'})
    empty_severity_alert = None
    empty_time_range = "No time range insights available."
    
    # Default return values to avoid unnecessary updates
    pie_fig, bar_fig, timeline_fig, heatmap_fig = empty_fig, empty_fig, empty_fig, empty_fig
    table_data, record_details, severity_alert = empty_table_data, empty_details, empty_severity_alert
    severity_insights, priority_insights = empty_fig, empty_fig
    time_range_message = empty_time_range
    csv_output = None

    if contents:
        # Process uploaded data
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        df_uploaded = pd.read_csv(io.StringIO(decoded.decode('utf-8')))

        # Preprocess and predict vulnerabilities
        df_preprocessed = preprocessor.transform(df_uploaded)
        predictions = model.predict(df_preprocessed)

        df_uploaded['bac_vulnerability'] = predictions[:, 0]
        df_uploaded['severity_level'] = predictions[:, 1].astype(float).round(2)  # Rounded to 2 decimal places
        df_uploaded['priority'] = predictions[:, 2].astype(float).round(2)  # Rounded to 2 decimal places
        df_uploaded['S.No'] = range(1, len(df_uploaded) + 1)

        # Extract hour information from timestamp
        df_uploaded['hour'] = pd.to_datetime(df_uploaded['timestamp']).dt.hour

        # Handle CSV download if triggered
        if ctx.triggered_id == 'download-csv' and csv_click:
            csv_output = dcc.send_data_frame(df_uploaded.to_csv, "BAC_vulnerabilities.csv")
            return [dash.no_update] * 10 + [csv_output]  # Prevent other outputs from being updated

        # If data was uploaded, generate the figures for the first time
        pie_fig = px.pie(df_uploaded, names='bac_vulnerability', title="Vulnerability Breakdown", hole=0.4, color_discrete_sequence=px.colors.qualitative.Bold)
        bar_fig = px.bar(df_uploaded, x='bac_vulnerability', title="Vulnerability Types", color='bac_vulnerability', color_discrete_sequence=px.colors.qualitative.Set3)
        timeline_fig = px.scatter(df_uploaded, x='timestamp', y='bac_vulnerability', title="Vulnerability Timeline", color='bac_vulnerability', color_discrete_sequence=px.colors.qualitative.Safe)
        heatmap_fig = px.density_heatmap(df_uploaded, x='severity_level', y='bac_vulnerability', title="Vulnerability Heatmap", color_continuous_scale=px.colors.sequential.Plasma)

        # High-risk vulnerabilities alert
        high_risk_vulns = df_uploaded[df_uploaded['severity_level'] > 7]
        if not high_risk_vulns.empty:
            severity_alert = html.Div([
                html.H5("⚠️ High Severity Vulnerabilities Detected!", style={'color': 'red', 'font-weight': 'bold'}),
                html.P(f"{len(high_risk_vulns)} instances of high-risk vulnerabilities detected.")
            ])

        # Severity and Priority insights
        severity_insights = px.histogram(df_uploaded, x='severity_level', title="Severity Levels Distribution")
        priority_insights = px.histogram(df_uploaded, x='priority', title="Priority Levels Distribution")

        # Time range insights (based on the hours when most vulnerabilities occur)
        peak_hours = df_uploaded['hour'].mode()
        if not peak_hours.empty:
            most_common_hour = peak_hours[0]
            time_range_message = f"Most vulnerabilities occur around {most_common_hour}:00. It is recommended to secure your system during this time."
        else:
            time_range_message = empty_time_range

        # Apply filters from dropdown (only affects table and histograms, not charts)
        if filter_input and filter_input != 'All':
            df_uploaded_filtered = df_uploaded[df_uploaded['bac_vulnerability'].isin([filter_input])]
        else:
            df_uploaded_filtered = df_uploaded

        # Update table and histograms based on the filtered data
        if len(df_uploaded_filtered) == 0:
            table_data = empty_table_data
            record_details = empty_details
        else:
            table_data = df_uploaded_filtered[['S.No', 'client_ip', 'bac_vulnerability', 'severity_level', 'priority']].to_dict('records')

            # On-click: Display expanded record details (with formatted sections and color-coding)
            if active_cell:
                selected_row = active_cell['row']
                if selected_row < len(df_uploaded_filtered):  # Check if selected_row is within bounds
                    selected_record = df_uploaded_filtered.iloc[selected_row]
                    vulnerability = selected_record['bac_vulnerability']
                    details = vulnerability_details.get(vulnerability, {})

                    # Beautiful formatted layout for record details
                    record_details = dbc.Card(
                        dbc.CardBody([
                            html.H3("RECORD DETAILS", style={'color': '#007bff', 'font-weight': 'bold'}),
                            html.H5("Request Details", className="card-title mt-4", style={'color': '#6c757d'}),
                            html.P([html.Span("Timestamp: ", style={'color': '#28a745'}), selected_record['timestamp']]),
                            html.P([html.Span("Method: ", style={'color': '#28a745'}), selected_record['method']]),
                            html.P([html.Span("Requested Resource: ", style={'color': '#28a745'}), selected_record['requested_resource']]),
                            html.P([html.Span("HTTP Version: ", style={'color': '#28a745'}), selected_record['http_version']]),
                            html.P([html.Span("Status Code: ", style={'color': '#28a745'}), selected_record['status_code']]),
                            html.P([html.Span("Response Size: ", style={'color': '#28a745'}), selected_record['response_size']]),
                            html.P([html.Span("Referrer: ", style={'color': '#28a745'}), selected_record['referrer']]),
                            html.P([html.Span("User Agent: ", style={'color': '#28a745'}), selected_record['user_agent']]),

                            html.H5("Access Details", className="card-title mt-4", style={'color': '#6c757d'}),
                            html.P([html.Span("User Role: ", style={'color': '#28a745'}), selected_record['user_role']]),
                            html.P([html.Span("Resource Sensitivity: ", style={'color': '#28a745'}), selected_record['resource_sensitivity']]),
                            html.P([html.Span("Access Type: ", style={'color': '#28a745'}), selected_record['access_type']]),
                            html.P([html.Span("Session Token: ", style={'color': '#28a745'}), selected_record['session_token']]),
                            html.P([html.Span("User ID: ", style={'color': '#28a745'}), selected_record['user_id']]),
                            html.P([html.Span("Owner ID: ", style={'color': '#28a745'}), selected_record['owner_id']]),

                            html.H5("Vulnerability Details", className="card-title mt-4", style={'color': '#6c757d'}),
                            html.P([html.Span("Detected Vulnerability: ", style={'color': '#28a745'}), vulnerability]),
                            html.P([html.Span("Severity Level: ", style={'color': '#28a745'}), selected_record['severity_level']]),
                            html.P([html.Span("Priority: ", style={'color': '#28a745'}), selected_record['priority']]),

                            html.H5("Potential Causes:", style={'color': '#6c757d'}),
                            html.Ul([html.Li(cause, style={'color': '#343a40'}) for cause in details.get('possible_causes', [])]),
                            html.H5("Tailored Mitigation Strategies:", style={'color': '#6c757d'}),
                            html.Ul([html.Li(strategy, style={'color': '#343a40'}) for strategy in details.get('mitigation_strategies', [])]),
                        ]),
                        style={'border': '1px solid #007bff', 'border-radius': '5px', 'padding': '10px', 'marginTop': '10px'}
                    )

    return [pie_fig, bar_fig, timeline_fig, heatmap_fig, table_data, record_details, severity_alert, severity_insights, priority_insights, time_range_message, csv_output]

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)
