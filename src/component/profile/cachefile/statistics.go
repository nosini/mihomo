package cachefile

import (
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

var keyStatistics = []byte("history")

// GetStatistics returns the saved connection statistics, or nil.
func (c *CacheFile) GetStatistics() []byte {
	if c.DB == nil {
		return nil
	}
	var data []byte
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketStatistics); bucket != nil {
			if v := bucket.Get(keyStatistics); v != nil {
				data = append([]byte(nil), v...)
			}
		}
		return nil
	})
	return data
}

func (c *CacheFile) SetStatistics(data []byte) {
	if c.DB == nil {
		return
	}
	err := c.DB.Update(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketStatistics)
		if err != nil {
			return err
		}
		return bucket.Put(keyStatistics, data)
	})
	if err != nil {
		log.Warnln("[CacheFile] write statistics to %s failed: %s", c.DB.Path(), err.Error())
	}
}
