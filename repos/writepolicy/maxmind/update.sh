#!/bin/bash
docker run --env-file app.env -v $(pwd):/usr/share/GeoIP maxmindinc/geoipupdate:latest
