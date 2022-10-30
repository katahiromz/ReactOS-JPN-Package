# font_setup.exe
add_executable(font_setup WIN32 font_setup.cpp font_setup_res.rc)
target_link_libraries(font_setup shlwapi)
