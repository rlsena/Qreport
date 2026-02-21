from vuln_check import get_new_vulns, generate_html_report
from send_mail import send_email

if __name__ == "__main__":

    count, titles, detections_count, PERIOD_DAYS = get_new_vulns()

    body = generate_html_report(
        count,
        titles,
        detections_count,
        PERIOD_DAYS
    )
    

    send_email(body)