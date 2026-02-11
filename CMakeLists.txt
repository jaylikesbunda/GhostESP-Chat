# GhostESP: Chat - P2P E2E Encrypted Chat on ESP32
# A spin-off of GhostESP: Revival firmware
cmake_minimum_required(VERSION 3.16)

# Set the components search path
set(EXTRA_COMPONENT_DIRS components)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ghostesp-chat)
