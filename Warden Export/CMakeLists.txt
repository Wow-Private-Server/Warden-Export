add_library(Warden_Export SHARED)

target_sources(Warden_Export PRIVATE
	"src/Main.cpp"
	"src/WardenExport.cpp"
)

target_include_directories(Warden_Export PUBLIC

	"Include"
)
