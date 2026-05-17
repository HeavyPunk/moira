package postgresql

type DatabaseConfig struct {
	Master   ReplicaConfig
	Replicas []ReplicaConfig
}

type ReplicaConfig struct {
	ConnectionString string
}
