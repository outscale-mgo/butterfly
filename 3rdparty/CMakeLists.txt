set(DPDK_SOURCE_DIR ${3RDPARTY_DIR}/dpdk)
set(PROTOBUF_SOURCE_DIR ${3RDPARTY_DIR}/protobuf)
set(PG_SOURCE_DIR ${3RDPARTY_DIR}/packetgraph)

ExternalProject_Add(dpdk
	SOURCE_DIR ${DPDK_SOURCE_DIR}
	DOWNLOAD_DIR ${PROJECT_SOURCE_DIR}
	DOWNLOAD_COMMAND git submodule update --init ${DPDK_SOURCE_DIR}
	PATCH_COMMAND make config T=x86_64-native-linuxapp-gcc
	CONFIGURE_COMMAND sed -i -- "s/CONFIG_RTE_EAL_IGB_UIO=y/CONFIG_RTE_EAL_IGB_UIO=n/" build/.config && sed -i -- "s/CONFIG_RTE_LIBRTE_PMD_PCAP=n/CONFIG_RTE_LIBRTE_PMD_PCAP=y/" build/.config && sed -i -- "s/CONFIG_RTE_KNI_KMOD=y/CONFIG_RTE_KNI_KMOD=n/" build/.config && sed -i -- "s/CONFIG_RTE_MACHINE=\"native\"/CONFIG_RTE_MACHINE=\"snb\"/" build/.config
	BINARY_DIR ${DPDK_SOURCE_DIR}
	BUILD_COMMAND ${PROJECT_SOURCE_DIR}/scripts/build_dpdk.sh ${DPDK_SOURCE_DIR}
	INSTALL_DIR ${DPDK_INSTALL_DIR}
	INSTALL_COMMAND  touch ${DPDK_INSTALL_DIR}/build && rm -rvf ${DPDK_INSTALL_DIR}/build && touch ${DPDK_INSTALL_DIR}/lib && rm  ${DPDK_INSTALL_DIR}/lib  && mv -vf ${DPDK_SOURCE_DIR}/build ${DPDK_INSTALL_DIR} && ln -s ${DPDK_SOURCE_DIR}/lib ${DPDK_INSTALL_DIR}/lib
	LOG_BUILD 1 Building dpdk)

ExternalProject_Add(packetgraph
	SOURCE_DIR ${PG_SOURCE_DIR}
	CONFIGURE_COMMAND RTE_SDK=${DPDK_INSTALL_DIR} ${PROJECT_SOURCE_DIR}/scripts/build_packetgraph.sh ${PG_SOURCE_DIR} ${PG_INSTALL_DIR}
	DOWNLOAD_DIR ${PROJECT_SOURCE_DIR}
	DOWNLOAD_COMMAND git submodule update --init ${PG_SOURCE_DIR}
	BINARY_DIR ${PG_INSTALL_DIR}
	BUILD_COMMAND ${PROJECT_SOURCE_DIR}/scripts/make_packetgraph.sh ${PG_SOURCE_DIR}
	INSTALL_DIR ${PG_INSTALL_DIR}
	INSTALL_COMMAND ${PROJECT_SOURCE_DIR}/scripts/make_packetgraph.sh ${PG_SOURCE_DIR} install
	LOG_BUILD 1 Building packetgraph)

# clean targets
add_custom_target(dependency-cleanup CLEAN
	rm -rf ${3RDPARTY_INSTALL_DIR}
	COMMENT Deleting dependencies)

add_custom_target(clean-pg
                  COMMAND rm -rf ${PROJECT_BINARY_DIR}/3rdparty/packetgraph-prefix/ ${PG_INSTALL_DIR} && make -C ${PROJECT_SOURCE_DIR}/3rdparty/packetgraph fclean)

add_custom_target(clean-dpdk
                  COMMAND rm -rf ${PROJECT_BINARY_DIR}/3rdparty/dpdk-prefix/ ${DPDK_INSTALL_DIR}
                  DEPENDS clean-pg)

add_custom_target(3rdparty)

add_dependencies(packetgraph dpdk)
