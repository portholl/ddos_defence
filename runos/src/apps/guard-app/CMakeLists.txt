target_sources(runos
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/GuardApp.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/GuardApp.hpp
)
target_include_directories(runos
    PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

