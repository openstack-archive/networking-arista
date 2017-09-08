# -*- mode: shell-script -*-

function install_lldp() {
    echo_summary "Installing LLDP"
    install_package lldpd
    restart_service lldpd
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
    iniset $ARISTA_ML2_CONF_FILE ml2_arista region_name $ARISTA_REGION_NAME

    if [ -n "${ARISTA_USE_FQDN+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE ml2_arista use_fqdn $ARISTA_USE_FQDN
    fi

    if [ -n "${ARISTA_ML2_SYNC_INTERVAL+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE ml2_arista sync_interval $ARISTA_ML2_SYNC_INTERVAL
    fi
    if [ -n "${ARISTA_SEC_GROUP_SUPPORT+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE ml2_arista sec_group_support $ARISTA_SEC_GROUP_SUPPORT
    fi
    if [ -n "${ARISTA_SWITCH_INFO+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE ml2_arista switch_info $ARISTA_SWITCH_INFO
    fi

    if [ -n "${ARISTA_PRIMARY_L3_HOST+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista primary_l3_host $ARISTA_PRIMARY_L3_HOST
    fi
    if [ -n "${ARISTA_PRIMARY_L3_HOST_USERNAME+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista primary_l3_host_username $ARISTA_PRIMARY_L3_HOST_USERNAME
    fi
    if [ -n "${ARISTA_PRIMARY_L3_HOST_PASSWORD+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista primary_l3_host_password $ARISTA_PRIMARY_L3_HOST_PASSWORD
    fi
    if [ -n "${ARISTA_SECONDARY_L3_HOST+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista secondary_l3_host $ARISTA_SECONDARY_L3_HOST
    fi
    if [ -n "${ARISTA_SECONDARY_L3_HOST_USERNAME+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista secondary_l3_host_username $ARISTA_SECONDARY_L3_HOST_USERNAME
    fi
    if [ -n "${ARISTA_SECONDARY_L3_HOST_PASSWORD+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista secondary_l3_host_password $ARISTA_SECONDARY_L3_HOST_PASSWORD
    fi
    if [ -n "${ARISTA_MLAG_CONFIG+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista mlag_config $ARISTA_MLAG_CONFIG
    fi
    if [ -n "${ARISTA_USE_VRF+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista use_vrf $ARISTA_USE_VRF
    fi
    if [ -n "${ARISTA_L3_SYNC_INTERVAL+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE l3_arista l3_sync_interval $ARISTA_L3_SYNC_INTERVAL
    fi

    if [ -n "${ARISTA_TYPE_DRIVER_SYNC_INTERVAL+x}" ]; then
        iniset $ARISTA_ML2_CONF_FILE arista_type_driver sync_interval $ARISTA_TYPE_DRIVER_SYNC_INTERVAL
    fi
    neutron_server_config_add $ARISTA_ML2_CONF_FILE
}

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    neutron_service_plugin_class_add "trunk"
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

