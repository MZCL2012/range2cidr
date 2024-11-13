package range2cidr

import (
	"fmt"
	"math/big"
	"net"
	"testing"
)

// Range2CIDRs 将IP范围转换为CIDR列表
func Range2CIDRs(startIP, endIP net.IP) ([]*net.IPNet, error) {
	// 输入验证
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("无效的IP地址")
	}

	// 标准化IP地址
	startIP = standardizeIP(startIP)
	endIP = standardizeIP(endIP)
	if len(startIP) != len(endIP) {
		return nil, fmt.Errorf("IP版本不匹配")
	}

	// 转换为big.Int
	startInt := new(big.Int).SetBytes(startIP)
	endInt := new(big.Int).SetBytes(endIP)

	// 验证范围
	if startInt.Cmp(endInt) > 0 {
		return nil, fmt.Errorf("起始IP大于结束IP")
	}

	var cidrs []*net.IPNet
	maxLen := len(startIP) * 8 // IPv4为32，IPv6为128

	for startInt.Cmp(endInt) <= 0 {
		// 计算当前IP到结束IP的差值
		diff := new(big.Int).Sub(endInt, startInt)
		diff.Add(diff, big.NewInt(1))

		// 找到最大的可能掩码
		maxSize := 0
		for i := 0; i < maxLen; i++ {
			blockSize := new(big.Int).Lsh(big.NewInt(1), uint(i))
			if blockSize.Cmp(diff) > 0 {
				break
			}
			maxSize = i
		}

		// 检查网络对齐
		for i := maxSize; i >= 0; i-- {
			mask := new(big.Int).Lsh(big.NewInt(1), uint(i))
			mask.Sub(mask, big.NewInt(1))
			networkStart := new(big.Int).And(startInt, new(big.Int).Not(mask))

			if networkStart.Cmp(startInt) == 0 {
				// 计算这个掩码下的最后一个地址
				networkEnd := new(big.Int).Or(startInt, mask)
				if networkEnd.Cmp(endInt) <= 0 {
					maxSize = i
					break
				}
			}
		}

		// 创建CIDR
		prefixLen := maxLen - maxSize
		ipBytes := make([]byte, len(startIP))
		startInt.FillBytes(ipBytes)

		cidr := &net.IPNet{
			IP:   net.IP(ipBytes),
			Mask: net.CIDRMask(prefixLen, maxLen),
		}
		cidrs = append(cidrs, cidr)

		// 移动到下一个网络
		increment := new(big.Int).Lsh(big.NewInt(1), uint(maxSize))
		startInt.Add(startInt, increment)
	}

	return cidrs, nil
}

// standardizeIP 标准化IP地址为4或16字节
func standardizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func TestRange2Cidr(t *testing.T) {
	// IPv4测试
	startIP4 := net.ParseIP("192.168.1.0")
	endIP4 := net.ParseIP("192.168.2.255")

	cidrs4, err := Range2CIDRs(startIP4, endIP4)
	if err != nil {
		fmt.Printf("IPv4转换失败: %v\n", err)
	} else {
		fmt.Printf("IPv4范围 %s - %s 转换为以下CIDR:\n", startIP4, endIP4)
		for _, cidr := range cidrs4 {
			fmt.Println(cidr)
		}
	}

	// IPv6测试
	startIP6 := net.ParseIP("2400:ee00:101c:6100:0:9d41:e2a9:efcf")
	endIP6 := net.ParseIP("2400:ee00:101c:6100:0:9d41:e2a9:efd7")

	cidrs6, err := Range2CIDRs(startIP6, endIP6)
	if err != nil {
		fmt.Printf("IPv6转换失败: %v\n", err)
	} else {
		fmt.Printf("\nIPv6范围 %s - %s 转换为以下CIDR:\n", startIP6, endIP6)
		for _, cidr := range cidrs6 {
			fmt.Println(cidr)
		}
	}
}


