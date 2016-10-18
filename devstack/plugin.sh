# -*- mode: shell-script -*-

function install_lldp() {
    echo_summary "Installing LLDP"
    install_package lldpd
    start_service lldpd
}

function install_arista_driver() {
    echo_summary "Installing Arista Driver"
    setup_develop $ARISTA_DIR
}

function configure_arista() {
    echo_summary "Configuring Neutron for Arista Driver"
    cp $ARISTA_ML2_CONF_SAMPLE $ARISTA_ML2_CONF_FILE

    iniset $ARISTA_ML2_CONF_FILE ml2_arista eapi_host $ARISTA_EAPI_HOST
    iniset $ARISTA_ML2_CONF_FILE ml2_arista eapi_username $ARISTA_EAPI_USERNAME
    iniset $ARISTA_ML2_CONF_FILE ml2_arista eapi_password $ARISTA_EAPI_PASSWORD
    iniset $ARISTA_ML2_CONF_FILE ml2_arista api_type $ARISTA_API_TYPE
    iniset $ARISTA_ML2_CONF_FILE ml2_arista region_name $REGION_NAME
}

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    if is_service_enabled "q-agt"; then
        install_lldp
    fi

elif [[ "$1" == "stack" && "$2" == "install" ]]; then
    install_arista_driver

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    configure_arista

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    # no-op
    :
fi

if [[ "$1" == "unstack" ]]; then
    # no-op
    :
fi

if [[ "$1" == "clean" ]]; then
    # no-op
    :
fi

