package querylog

type NoneWriter struct{}

func NewNoneWriter() *NoneWriter {
	return &NoneWriter{}
}

func (d *NoneWriter) Write(*LogEntry) {
	// Nothing to do
}

func (d *NoneWriter) CleanUp() {
	// Nothing to do
}
