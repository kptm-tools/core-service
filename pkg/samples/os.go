package samples

import (
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/kptm-tools/common/common/pkg/results/tools"
)

// predefinedOSProfiles holds a set of realistic OS data we can choose from.
var predefinedOSProfiles = []tools.OSData{
	{
		Name:        "Ubuntu 22.04 LTS (Jammy Jellyfish)",
		Family:      "Linux",
		Type:        "general-purpose",
		CPE:         "cpe:/o:canonical:ubuntu_linux:22.04",
		FingerPrint: "OS:SCAN(V=7.92%E=4%D=5/2%OT=22%CT=1%CU=30432%PV=Y%DS=1%DC=D%G=Y%M=459E4E%TM=6282E008%P=x86_64-pc-linux-gnu)",
	},
	{
		Name:        "Windows Server 2022",
		Family:      "Windows",
		Type:        "general-purpose",
		CPE:         "cpe:/o:microsoft:windows_server_2022",
		FingerPrint: "OS:SCAN(V=7.92%E=4%D=5/2%OT=443%CT=1%CU=32432%PV=Y%DS=2%DC=I%G=Y%M=5B3E7A%TM=6283A01F%P=x86_64-pc-win32)",
	},
	{
		Name:        "Cisco IOS 15.1",
		Family:      "IOS",
		Type:        "router",
		CPE:         "cpe:/o:cisco:ios:15.1",
		FingerPrint: "OS:SCAN(V=7.92%E=4%D=5/2%OT=23%CT=1%CU=43432%PV=N%DS=5%DC=D%G=Y%M=5A9F7B%TM=6281B02C%P=powerpc-cisco-ios)",
	},
	{
		Name:        "Apple macOS 14 Sonoma",
		Family:      "Darwin",
		Type:        "general-purpose",
		CPE:         "cpe:/o:apple:macos:14",
		FingerPrint: "OS:SCAN(V=7.92%E=4%D=5/2%OT=22%CT=1%CU=35432%PV=Y%DS=1%DC=D%G=Y%M=489E1E%TM=6284E03A%P=x86_64-apple-darwin)",
	},
}

func generateOSData() tools.OSData {
	gofakeit.ShuffleAnySlice(predefinedOSProfiles)
	selectedOSProfile := predefinedOSProfiles[0]

	return tools.OSData{
		Name:            selectedOSProfile.Name,
		Accuracy:        gofakeit.Number(85, 100),
		Family:          selectedOSProfile.Family,
		Type:            selectedOSProfile.Type,
		FingerPrint:     selectedOSProfile.FingerPrint,
		CPE:             selectedOSProfile.CPE,
		Vulnerabilities: generateVuln(4, time.Now()), // Updated to use new signature
	}
}
