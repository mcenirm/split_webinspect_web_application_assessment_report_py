# split_webinspect_web_application_assessment_report_py
Split a WebInspect Web Application Assessment Report

Once upon a time, we received a large PDF of a WebInspect report. I wanted a better way to organize the vulnerabilities.

Step 0: Install prerequisites

```shell
sudo apt install poppler python3.8
```

Step 1: Convert PDF to plain text

```shell
pdftotext -nopgbrk REPORTNAME.pdf REPORTNAME.txt
```

Step 2: Split text version

```shell
python3.8 REPORTNAME.txt REPORTNAME.parts/
```
