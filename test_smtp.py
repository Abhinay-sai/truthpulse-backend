import smtplib

try:
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=5)
    server.login('abhinaysai21@gmail.com', 'ggxcfhcnitsejzro')
    print("SUCCESS: SMTP login successful!")
    server.quit()
except Exception as e:
    print(f"FAILED: {e}")
