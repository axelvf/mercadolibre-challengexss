
#!/bin/bash

docker build --rm -t mercadolibre/challengexss:1.0 .
docker run -i -t mercadolibre/challengexss:1.0