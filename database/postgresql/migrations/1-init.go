package migrations

type Migration struct {
	Number     int64
	ForwardSQL string
}

func Init_01() Migration {
	return Migration{
		Number:     1,
		ForwardSQL: "",
	}
}
