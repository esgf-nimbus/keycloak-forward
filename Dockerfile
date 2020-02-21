FROM continuumio/miniconda3:4.7.12 as build

WORKDIR /build

COPY meta.yaml .
COPY setup.py .
COPY keycloak_forward/ keycloak_forward/

RUN conda install conda-build anaconda-client && \
      conda build -c conda-forge .

FROM continuumio/miniconda3:4.7.12

COPY keycloak_forward/sample.cfg /etc/keycloak/keycloak.cfg
COPY --from=build /opt/conda/conda-bld /opt/conda/conda-bld

ENV KEYCLOAK_FORWARD_CONFIG /etc/keycloak/keycloak.cfg

RUN conda update -n base -c defaults conda && \
      conda install -c conda-forge --use-local keycloak-forward -y

ENTRYPOINT ["gunicorn", "keycloak_forward:create_app()", "-b", "0.0.0.0:8888"]
