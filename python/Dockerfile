FROM fedora:latest

LABEL version="1.0"
LABEL description="idk maybe later"

USER 0

EXPOSE 8000
EXPOSE 80

ADD app.py helpers.py report_helpers.py s3_helpers.py requirements.txt start.sh /
ADD index.html style.css scripts.js loading.gif  /var/www/html/
ADD bootstrap /var/www/html/bootstrap

# RUN yum install -y python3-tkinter
RUN yum install -y httpd \
   && pip3 install -r requirements.txt \
   && chmod 777 /var/www/html/ \
   && chmod 777 /start.sh \
   && echo "ServerName localhost" >> /etc/httpd/conf/httpd.conf

CMD ["/bin/bash", "/start.sh"]
