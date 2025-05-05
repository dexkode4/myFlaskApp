# CONTRIBUTING

## How to run the Dockerfile locally

# Build image
docker build -t IMAGE_NAME .

# run
docker run -dp 5005:5000 -w /app -v "$(pwd):/app" IMAGE_NAME sh -c "flask run"


## How to install requirements
 python3 -m pip install -r requirements.txt
