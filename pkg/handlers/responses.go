package handlers

type FusionAuthErrorResponse struct {
	GeneralErrors []GeneralError
	FieldErrors   map[string][]FieldError `json:"fieldErrors"`
}

type GeneralError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type FieldError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
