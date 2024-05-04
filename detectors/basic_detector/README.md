# Malware classifier

This folder works !


### Start the docker

```bash
docker build -t basic_detector .
docker run --name basic_detector \
    -v "$(pwd)"/../data/:/app/samples \
    -v "$(pwd)":/app/results \
    -d basic_detector
# Replace the actual <mount_point> by a real one like "$(pwd)"/target where are stored samples
```

### How does it work ?

Bash script execute hourly at XX:30 to download the latest samples from Malware Bazaar and store them in the mounted volume.
Zipped samples are generated roughly every hour by Malware Bazaar.

### WIP

- [ ] Optimize the Dockerfile to be memory  and running time efficient (check `docker ps -s`)
- [ ] Optimize the logging part by using journalctl