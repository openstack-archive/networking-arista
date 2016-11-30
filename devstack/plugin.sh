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
    iniset $ARISTA_ML2_CONF_FILE ml2_arista use_fqdn $ARISTA_USE_FQDN
    iniset $ARISTA_ML2_CONF_FILE ml2_arista sync_interval $ARISTA_ML2_SYNC_INTERVAL
    iniset $ARISTA_ML2_CONF_FILE ml2_arista sec_group_support $ARISTA_SEC_GROUP_SUPPORT
    iniset $ARISTA_ML2_CONF_FILE ml2_arista switch_info $ARISTA_SWITCH_INFO

    iniset $ARISTA_ML2_CONF_FILE l3_arista primary_l3_host $ARISTA_PRIMARY_L3_HOST
    iniset $ARISTA_ML2_CONF_FILE l3_arista primary_l3_host_username $ARISTA_PRIMARY_L3_HOST_USERNAME
    iniset $ARISTA_ML2_CONF_FILE l3_arista primary_l3_host_password $ARISTA_PRIMARY_L3_HOST_PASSWORD
    iniset $ARISTA_ML2_CONF_FILE l3_arista secondary_l3_host $ARISTA_SECONDARY_L3_HOST
    iniset $ARISTA_ML2_CONF_FILE l3_arista secondary_l3_host_username $ARISTA_SECONDARY_L3_HOST_USERNAME
    iniset $ARISTA_ML2_CONF_FILE l3_arista secondary_l3_host_password $ARISTA_SECONDARY_L3_HOST_PASSWORD
    iniset $ARISTA_ML2_CONF_FILE l3_arista mlag_config $ARISTA_MLAG_CONFIG
    iniset $ARISTA_ML2_CONF_FILE l3_arista use_vrf $ARISTA_USE_VRF
    iniset $ARISTA_ML2_CONF_FILE l3_arista l3_sync_interval $ARISTA_L3_SYNC_INTERVAL

    iniset $ARISTA_ML2_CONF_FILE arista_type_driver sync_interval $ARISTA_TYPE_DRIVER_SYNC_INTERVAL
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

