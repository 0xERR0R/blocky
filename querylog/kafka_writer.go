package querylog

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/confluentinc/confluent-kafka-go.v1/kafka"
)

type KafkaWriter struct {
	kafka *kafka.Producer
	topic string
}

func NewKafkaWriter(target string) (*KafkaWriter, error) {
	var config map[string]interface{}
	err := json.Unmarshal([]byte(target), &config)

	if err != nil {
		return nil, fmt.Errorf("can't parse json object: %w", err)
	}

	configMap := &kafka.ConfigMap{}

	topic := ""

	for k, v := range config {
		valStr := fmt.Sprintf("%v", v)
		if strings.Contains(valStr, "env:$") {
			envVar, ok := os.LookupEnv(strings.Replace(valStr, "env:$", "", 1))
			if ok {
				v = envVar
			} else {
				log.Log().Warnf("tried to evaluate %v as environment variable, but the environment variable doesn't exist", valStr)
			}
		}

		if k == "topic" {
			topic = fmt.Sprintf("%v", v)
		} else {
			configMap.SetKey(k, v)
		}
	}

	p, err := kafka.NewProducer(configMap)
	if err != nil {
		return nil, fmt.Errorf("can't create kafka producer: %w", err)
	}

	return &KafkaWriter{
		kafka: p,
		topic: topic,
	}, nil
}

func (k *KafkaWriter) Write(entry *LogEntry) {
	domain := util.ExtractDomain(entry.Request.Req.Question[0])
	eTLD, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	e := &logEntry{
		RequestTS:     &entry.Start,
		ClientIP:      entry.Request.ClientIP.String(),
		ClientName:    strings.Join(entry.Request.ClientNames, "; "),
		DurationMs:    entry.DurationMs,
		Reason:        entry.Response.Reason,
		ResponseType:  entry.Response.RType.String(),
		QuestionType:  dns.TypeToString[entry.Request.Req.Question[0].Qtype],
		QuestionName:  domain,
		EffectiveTLDP: eTLD,
		Answer:        util.AnswerToString(entry.Response.Res.Answer),
		ResponseCode:  dns.RcodeToString[entry.Response.Res.Rcode],
	}

	json, err := json.Marshal(e)

	if err != nil {
		log.Log().Errorf("Error logging entry to kafka: %v", err)
		return
	}

	k.kafka.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &k.topic, Partition: kafka.PartitionAny},
		Value:          json,
	}, nil)
}

func (k *KafkaWriter) CleanUp() {
	// nothing to clean up for kafka logger
}
