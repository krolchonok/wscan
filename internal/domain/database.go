package domain

import (
	"strings"
	"unicode"
)

// DatabaseFamily identifies a database from whole words, with aliases sharing
// the same family. The first matching word wins (the primary product in titles).
func DatabaseFamily(text string) string {
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for _, word := range words {
		switch word {
		case "redis":
			return "Redis"
		case "mysql", "mariadb":
			return "MySQL / MariaDB"
		case "postgres", "postgresql", "pgsql", "psql":
			return "PostgreSQL"
		case "mssql", "sqlserver":
			return "MSSQL"
		case "oracle":
			return "Oracle"
		case "mongodb", "mongo":
			return "MongoDB"
		case "cassandra", "cql":
			return "Cassandra"
		case "couchdb":
			return "CouchDB"
		case "db2":
			return "DB2"
		case "informix":
			return "Informix"
		case "maxdb":
			return "MaxDB"
		case "memcached":
			return "Memcached"
		case "clickhouse":
			return "ClickHouse"
		}
	}
	if strings.Contains(strings.ToLower(text), "ms-sql") {
		return "MSSQL"
	}
	return ""
}

// ServiceDatabase uses port hints only when discovery did not identify a service.
func ServiceDatabase(s Service) string {
	if family := DatabaseFamily(s.Name); family != "" {
		return family
	}
	if s.Name != "" && s.Name != "unknown" {
		return ""
	}
	if family := DatabaseFamily(s.PortService); family != "" {
		return family
	}
	switch s.Port {
	case 6379:
		return "Redis"
	case 3306:
		return "MySQL / MariaDB"
	case 5432:
		return "PostgreSQL"
	case 1433:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 27017:
		return "MongoDB"
	case 9042:
		return "Cassandra"
	case 5984:
		return "CouchDB"
	case 50000:
		return "DB2"
	case 11211:
		return "Memcached"
	}
	return ""
}
