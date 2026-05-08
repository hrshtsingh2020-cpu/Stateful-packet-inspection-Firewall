import streamlit as st
import pandas as pd
import sqlite3
import time
import altair as alt

st.set_page_config(page_title='SPI Firewall Monitor', layout='wide')
st.title('🛡️ SPI Firewall: Real-Time Security Monitor')

def fetch_logs():
    try:
        conn = sqlite3.connect('firewall_logs.db')
        df = pd.read_sql('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100', conn)
        conn.close()
        return df
    except: return pd.DataFrame()

# UI Layout [cite: 306, 307]
metric_col, chart_col = st.columns([1, 2])
log_placeholder = st.empty()

while True:
    data = fetch_logs()
    if not data.empty:
        with metric_col:
            st.metric('Total Packets', len(data))
            st.metric('Threats Blocked', (data['status'] == 'DROP').sum())
            st.metric('Active Sessions', (data['reason'] == 'ESTABLISHED').sum())
        
        with chart_col:
            chart_data = data['status'].value_counts().reset_index()
            chart_data.columns = ['Status', 'Count']
            bar = alt.Chart(chart_data).mark_bar().encode(x='Status', y='Count', 
                  color=alt.condition(alt.datum.Status == 'DROP', alt.value('#E41E26'), alt.value('#1F7A4E')))
            st.altair_chart(bar, use_container_width=True)

        with log_placeholder.container():
            st.subheader('Live Connection Log')
            st.dataframe(data.style.apply(lambda x: ['background-color: #ffcccc' if x.status == 'DROP' else '' for i in x], axis=1))
    
    time.sleep(2)
    st.rerun()
