import streamlit as st
import pandas as pd
import re
from datetime import datetime

LOG_PATH = "app.log"

@st.cache_data(ttl=60)
def load_logs():
    entries = []
    pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+(.*)$')
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            m = pattern.match(line)
            if m:
                ts_str = m.group(1)
                msg = m.group(2)
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
                    entries.append((ts, msg))
                except ValueError:
                    continue
    df = pd.DataFrame(entries, columns=["timestamp", "message"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.set_index("timestamp")
    df["suspeita"] = df["message"].str.contains(r"\[SUSPEITA SQLi\]|\[ERRO JSON\]", regex=True)
    return df

df = load_logs()

st.title("Dashboard de Segurança")
st.markdown("Visualização de tentativas de login e detecções de ataques.")

total = len(df)
suspeitas = df["suspeita"].sum()
st.metric("Total de eventos", total, delta=f"{suspeitas} suspeitos")

df_time = df.resample("1T").size().rename("total")
df_susp = df[df["suspeita"]].resample("1T").size().rename("suspeitas")
ser = pd.concat([df_time, df_susp], axis=1).fillna(0)

st.line_chart(ser)

st.subheader("Últimas 10 detecções suspeitas")
st.dataframe(df[df["suspeita"]].sort_index(ascending=False).head(10))

st.sidebar.header("Filtros")
ip_filter = st.sidebar.text_input("Filtrar por IP (ex: 127.0.0.1)")
if ip_filter:
    filtered = df[df["message"].str.contains(ip_filter)]
    st.subheader(f"Eventos do IP {ip_filter}")
    st.dataframe(filtered)
