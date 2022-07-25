#!/bin/sh

set -x
set +e

PLANTUML=https://github.com/plantuml/plantuml/releases/download/v1.2022.6/plantuml-1.2022.6.jar

wget -O /tmp/plantuml.jar $PLANTUML

for PUML in *.puml; do
    java -Djava.awt.headless=true -jar /tmp/plantuml.jar $PUML
done
