package ipscan

func (r *Runner) GetIpAddr(ip string) (country, area string, err error) {
	res, err := r.options.QQwry.Find(ip)
	if err != nil {
		return
	}
	country = res.Country
	area = res.Area
	return
}
