FROM python:3.13.2
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt
COPY . .
CMD sh -c "python update_password_field.py && gunicorn --bind 0.0.0.0:80 'app:create_app()'"
