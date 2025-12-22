package normalizer

// OIDMap contiene los OIDs SNMP utilizados para cada marca y tipo de dato
type OIDMap struct {
	Model               string
	SerialNumber        string
	FirmwareVersion     string
	Description         string
	GeneralStatus       string
	OverallStatus       string
	DoorStatus          string
	TonerBlackPercent   string
	TonerBlackAlt       string
	TonerCyanPercent    string
	TonerMagentaPercent string
	TonerYellowPercent  string
	DrumPercent         string
	TotalPages          string
	TotalPagesAlt       string
	PagesBN             string // B&W pages propietario
	PagesColor          string // Color pages propietario
}

// OIDMaps contiene los OIDs para cada marca
var OIDMaps = map[string]*OIDMap{
	"Samsung": {
		Model:               "1.3.6.1.4.1.236.11.5.11.40.27.1.0",
		Description:         "1.3.6.1.2.1.1.1.0",
		GeneralStatus:       "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackPercent:   "1.3.6.1.4.1.236.11.5.11.51.13.1.0",
		TonerBlackAlt:       "1.3.6.1.4.1.236.11.5.11.51.13.1.0",
		TonerCyanPercent:    "1.3.6.1.4.1.236.11.5.11.51.14.1.0",
		TonerMagentaPercent: "1.3.6.1.4.1.236.11.5.11.51.15.1.0",
		TonerYellowPercent:  "1.3.6.1.4.1.236.11.5.11.51.16.1.0",
		TotalPages:          "1.3.6.1.4.1.236.11.5.11.50.11.1.1.0",
		TotalPagesAlt:       "1.3.6.1.4.1.236.11.5.11.50.11.1.1.0",
		PagesBN:             "1.3.6.1.4.1.236.11.5.11.53.11.1.2.0",
		PagesColor:          "1.3.6.1.4.1.236.11.5.11.53.11.1.1.0",
	},
	"HP": {
		Model:               "1.3.6.1.2.1.43.5.1.1.16.1",
		SerialNumber:        "1.3.6.1.2.1.43.5.1.1.17.1",
		Description:         "1.3.6.1.2.1.1.1.0",
		GeneralStatus:       "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackPercent:   "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.19.0",
		TonerCyanPercent:    "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.20.0",
		TonerMagentaPercent: "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.21.0",
		TonerYellowPercent:  "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.22.0",
		TotalPages:          "1.3.6.1.2.1.43.10.2.1.4.1.1",
		PagesBN:             "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.6.0",
		PagesColor:          "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.7.0",
	},
	"Xerox": {
		Model:         "1.3.6.1.4.1.253.8.53.3.2.1.1.0",
		Description:   "1.3.6.1.2.1.1.1.0",
		GeneralStatus: "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackAlt: "1.3.6.1.4.1.253.8.53.13.2.1.5.1.20.101",
		TotalPages:    "1.3.6.1.2.1.43.10.2.1.4.1.1",
		TotalPagesAlt: "1.3.6.1.4.1.253.8.53.13.2.1.6.1.20.101",
		PagesBN:       "1.3.6.1.4.1.253.8.53.13.2.1.6.1.20.101",
		PagesColor:    "1.3.6.1.4.1.253.8.53.13.2.1.6.1.20.102",
	},
	"Brother": {
		Model:             "1.3.6.1.2.1.43.5.1.1.16.1",
		Description:       "1.3.6.1.2.1.1.1.0",
		GeneralStatus:     "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackPercent: "1.3.6.1.4.1.2435.2.4.3.99.3.3.1.0",
		TotalPages:        "1.3.6.1.2.1.43.10.2.1.4.1.1",
	},
	"Ricoh": {
		Model:             "1.3.6.1.2.1.43.5.1.1.16.1",
		Description:       "1.3.6.1.2.1.1.1.0",
		GeneralStatus:     "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackPercent: "1.3.6.1.4.1.367.3.2.1.2.25.1.1.1.0",
		TotalPages:        "1.3.6.1.2.1.43.10.2.1.4.1.1",
	},
	"Canon": {
		Model:             "1.3.6.1.2.1.43.5.1.1.16.1",
		Description:       "1.3.6.1.2.1.1.1.0",
		GeneralStatus:     "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackPercent: "1.3.6.1.4.1.1602.1.2.1.3.0",
		TotalPages:        "1.3.6.1.2.1.43.10.2.1.4.1.1",
	},
	"Kyocera": {
		Model:             "1.3.6.1.2.1.43.5.1.1.16.1",
		Description:       "1.3.6.1.2.1.1.1.0",
		GeneralStatus:     "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackPercent: "1.3.6.1.4.1.1347.42.3.1.1.1.3.1.0",
		TotalPages:        "1.3.6.1.4.1.1347.42.3.1.1.1.1.1",
		PagesBN:           "1.3.6.1.4.1.1347.42.3.1.2.1.1.1.1",
		PagesColor:        "1.3.6.1.4.1.1347.42.3.1.2.1.1.1.3",
	},
}

// GetOIDs retorna el mapa de OIDs para una marca
func GetOIDs(brand string) *OIDMap {
	if oids, ok := OIDMaps[brand]; ok {
		return oids
	}
	// Retornar OIDs genéricos para marcas desconocidas
	return &OIDMap{
		Model:             "1.3.6.1.2.1.43.5.1.1.16.1",
		Description:       "1.3.6.1.2.1.1.1.0",
		GeneralStatus:     "1.3.6.1.2.1.25.3.2.1.5.1",
		TonerBlackPercent: "1.3.6.1.2.1.43.11.1.1.9.1.1",
		TotalPages:        "1.3.6.1.2.1.43.10.2.1.4.1.1",
	}
}
