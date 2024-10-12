FROM python:3.12.0-slim-buster

# Set the working directory
WORKDIR /flip

COPY app.py flag.txt models.py requirements.txt /flip/
RUN apt update -y && apt upgrade -y && apt install 
RUN apt install python3-pip -y 
COPY templates/ /flip/templates/
COPY static/ /flip/static/
COPY entrypoint.sh /flip/entrypoint.sh
RUN chmod +x /flip/entrypoint.sh
RUN pip install -r requirements.txt --no-cache-dir

ENV FLASK_APP=app.py
ENV FLASK_ENVIRONMENT=production
EXPOSE 6789

ENTRYPOINT [ "./entrypoint.sh" ]
