import os
import sys
import logging
from karton.core import Config, Producer, Task, Resource

config = Config("karton.ini")
producer = Producer(config)

filename = sys.argv[1]
with open(filename, "rb") as f:
    contents = f.read()

resource = Resource(os.path.basename(filename), contents)

task = Task({"type": "sample", "kind": "raw"})

task.add_payload("sample", resource)
task.add_payload("tags", ["simple_producer"])
task.add_payload("additional_info", ["This sample has been added by simple producer example"])

logging.info('pushing file to karton: %s, task: %s' % (filename, task))
producer.send_task(task)