import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo

#carrega variaveis de ambiente
load_dotenv()

#Puxar as vulnerabilidades novas da API do Qualys, filtrando por status "New" e considerando o período definido na variável de ambiente TIMEFRAME (em dias). 
# #O script deve retornar a quantidade total de vulnerabilidades novas, uma lista com os títulos e severidades dessas vulnerabilidades, a quantidade total de detecções e o período considerado.
def get_new_vulns():

    USERNAME = os.getenv("QUALYS_USER")
    PASSWORD = os.getenv("QUALYS_PASS")
    PERIOD_DAYS = int(os.getenv("TIMEFRAME"))

    BASE_URL = "https://qualysapi.qg4.apps.qualys.com"

    DETECTION_URL = f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/"
    KNOWLEDGE_URL = f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/"

    headers = {
        "X-Requested-With": "Python Script"
    }

    seven_days_ago = (
        datetime.utcnow() - timedelta(days=int(os.getenv("TIMEFRAME")))
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    params = {
        "action": "list",
        "status": "New",
        "detection_updated_since": seven_days_ago,
        "truncation_limit": "0"
    }

    response = requests.get(
        DETECTION_URL,
        headers=headers,
        params=params,
        auth=(USERNAME, PASSWORD)
    )

    root = ET.fromstring(response.content)

    valid_qids = set()

    for d in root.findall(".//DETECTION"):

        status = d.find("STATUS")
        ignored = d.find("IGNORED")
        disabled = d.find("DISABLED")
        superseded = d.find("IS_SUPERSEDED")
        qid = d.find("QID")

        if status is None or qid is None:
            continue

        if status.text != "New":
            continue

        if (
            (ignored is not None and ignored.text == "1") or
            (disabled is not None and disabled.text == "1") or
            (superseded is not None and superseded.text == "1")
        ):
            continue

        valid_qids.add(qid.text)

    vulnerabilities = []

    if valid_qids:

        kb_params = {
            "action": "list",
            "ids": ",".join(valid_qids)
        }

        kb_response = requests.get(
            KNOWLEDGE_URL,
            headers=headers,
            params=kb_params,
            auth=(USERNAME, PASSWORD)
        )

        kb_root = ET.fromstring(kb_response.content)

        severity_map = {
            "1": "Info",
            "2": "Low",
            "3": "Medium",
            "4": "High",
            "5": "Critical"
        }

        for v in kb_root.findall(".//VULN"):

            title_elem = v.find("TITLE")
            sev_elem = v.find("SEVERITY_LEVEL")

            title = title_elem.text.strip() if title_elem is not None else None
            sev_raw = sev_elem.text.strip() if (sev_elem is not None and sev_elem.text) else None

            if title:

                if sev_raw and sev_raw in severity_map:
                    severity_text = severity_map[sev_raw]
                else:
                    severity_text = sev_raw.capitalize() if sev_raw else "Unknown"

                vulnerabilities.append({
                    "title": title,
                    "severity": severity_text
                })

    detections = root.findall(".//DETECTION")
    
    return len(valid_qids), vulnerabilities,len(detections), PERIOD_DAYS

#gerar o HTML de saida do relatório

def generate_html_report(count, vulnerabilities,detections,PERIOD_DAYS):

    # Timezone Brasil
    today = datetime.now(
        ZoneInfo("America/Sao_Paulo")
        ).strftime("%d/%m/%Y %H:%M (%Z)")

    #Checar se existe vulnerabilidade.
    if count == 0:
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color:#f4f6f7; padding:20px;">

            <!-- HEADER -->
            <img src="cid:logo_cid"
             style="display:block; margin:0 auto 15px auto; max-width:180px;">

            <div style="background-color:#2c3e50;padding:25px;border-radius:8px;color:white;text-align:center;">
                <h2 style="margin:0;">Relatório de Vulnerabilidades</h2>
                <p style="margin:5px 0 0 0;font-size:14px;">
                    Gerado em: {today}
                </p>
            </div>

            <div style="margin-top:20px;padding:20px;background:white;border-radius:8px;">
                <h3 style="margin-top:0;">Resumo Executivo</h3>
                <p style="font-size:16px;">
                    Caro cliente,<br><br>
                    Temos uma ótima notícia! Não foram identificadas novas vulnerabilidades em seu ambiente nos últimos {PERIOD_DAYS} dias.<br><br>
                    Continuaremos monitorando ativamente para garantir que seu ambiente permaneça seguro. 
                </p>
            </div>

            <!-- FOOTER -->
            <div style="margin-top:25px;text-align:center;color:#7f8c8d;font-size:12px;">
                Relatório automático gerado via API Qualys - Powered by Brainwalk
            </div>

        </body>
        </html>
        """
    
    #Fluxo alternativo. Vulnerabilidade encontrada. Gerar relatório completo.
    else:


        # Contagem por severidade
        severity_counter = Counter([v["severity"] for v in vulnerabilities])



        # Cores por severidade
        severity_colors = {
            "Critical": "#c0392b",
            "High": "#e67e22",
            "Medium": "#f1c40f",
            "Low": "#27ae60",
            "Info": "#2980b9",
            "Unknown": "#7f8c8d"
        }

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color:#f4f6f7; padding:20px;">

            <!-- HEADER -->
            <img src="cid:logo_cid"
            style="display:block; margin:0 auto 15px auto; max-width:180px;">

            <div style="background-color:#2c3e50;padding:25px;border-radius:8px;color:white;text-align:center;">
                <h2 style="margin:0;">Relatório de Vulnerabilidades</h2>
                <p style="margin:5px 0 0 0;font-size:14px;">
                    Gerado em: {today}
                </p>
            </div>

            
            <!-- RESUMO EXECUTIVO -->
            <div style="margin-top:20px;padding:20px;background:white;border-radius:8px;">
                <h3 style="margin-top:0;">Resumo Executivo</h3>
                <p style="font-size:16px;">
                    Caro cliente,<br><br>
                    Apresentamos abaixo as vulnerabilidades identificadas em seu ambiente nos últimos {PERIOD_DAYS} dias.<br>
                    Essas informações permitem acompanhar novas exposições, priorizar correções e manter seu ambiente cada vez mais seguro.<br><br>


                    Total de novas vulnerabilidades identificadas:<br>
                    O ambiente tem <strong>{count}</strong> vulnerabilidades novas distribuidas em <strong>{detections}</strong> detecções.               
                </p>

                <table width="100%" style="margin-top:15px;">
                    <tr>
        """

        # Cards de severidade
        for severity in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]:
            qty = severity_counter.get(severity, 0)
            if qty > 0:
                color = severity_colors.get(severity, "#7f8c8d")

                html += f"""
                    <td style="padding:10px;text-align:center;">
                        <div style="
                            background-color:{color};
                            color:white;
                            padding:12px;
                            border-radius:6px;
                            font-weight:bold;">
                            {severity}: {qty}
                        </div>
                    </td>
                """

        html += """
                    </tr>
                </table>
            </div>

            <!-- DETALHAMENTO -->
            <div style="margin-top:20px;padding:20px;background:white;border-radius:8px;">
                <h3 style="margin-top:0;">Detalhamento das Vulnerabilidades</h3>
                <table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
                    <tr style="background-color:#ecf0f1;font-weight:bold;">
                        <td width="20%">Severidade</td>
                        <td width="80%">Título</td>
                    </tr>
        """

        # Ordena por criticidade
        severity_order = {
            "Critical": 1,
            "High": 2,
            "Medium": 3,
            "Low": 4,
            "Info": 5,
            "Unknown": 6
        }

        vulnerabilities_sorted = sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x["severity"], 6)
        )

        for vuln in vulnerabilities_sorted:

            color = severity_colors.get(vuln["severity"], "#7f8c8d")

            html += f"""
                <tr>
                    <td style="color:{color};font-weight:bold;">
                        {vuln['severity']}
                    </td>
                    <td>
                        {vuln['title']}
                    </td>
                </tr>
            """

        html += """
                </table>
            </div>

            <!-- FOOTER -->
            <div style="margin-top:25px;text-align:center;color:#7f8c8d;font-size:12px;">
                Relatório automático gerado via API Qualys - Powered by Brainwalk
            </div>

        </body>
        </html>
        """

    return html