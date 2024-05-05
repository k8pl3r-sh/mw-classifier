# Use a Python base image
FROM python:3.11-slim

WORKDIR /app

COPY basic_detector.py .
COPY run_detector.sh .
COPY saved_detector.pkl .

RUN chmod +x run_detector.sh

COPY requirements.txt .
RUN pip install -r requirements.txt

# Define the volume mount point
# VOLUME /app/samples
# VOLUME /app/results


# Run the bash script when the container launches
CMD ["./run_detector.sh"]
