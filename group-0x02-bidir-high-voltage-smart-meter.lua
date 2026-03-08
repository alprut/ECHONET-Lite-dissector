-- ########################################################
-- ECHONET Lite
-- Bidirectional High Voltage Smart Electric Energy Meter Class
-- Wireshark dissector
-- ########################################################
--
--   Author : Yasuyuki Kozakai
--   Version: 0.0.1
--   License: MIT
--
-- ########################################################
--
--  Copyright (c) 2026 Yasuyuki Kozakai
--  This software is released under the MIT License.
--  http://opensource.org/licenses/MIT
--
-- Bidirectional High Voltage Smart Electric Energy Meter Class
--   Class group code : 0x02
--   Class code       : 0x8F
--   Spec             : ECHONET Appendix Release R rev.4, Section 3.3.42
--
local devicesuperclass = require("device-superclass")
local list = require("echonet-lite-codelist")
local properties = {
    [0xC0] = "Bルート識別番号",
    [0xC1] = "月間最大需要電力（正方向、逆方向計測値）",
    [0xC2] = "累積最大需要電力（正方向、逆方向計測値）",
    [0xC3] = "定時需要電力（30分平均電力）（正方向、逆方向計測値）",
    [0xC4] = "需要電力有効桁数",
    [0xC5] = "需要電力単位",
    [0xC6] = "需要電力計測値履歴（正方向計測値）",
    [0xC7] = "累積最大需要電力単位",
    [0xC8] = "需要電力計測値履歴（逆方向計測値）",
    [0xCA] = "力測積算無効電力量（遅れ）計測値（正方向、逆方向計測値）",
    [0xCB] = "定時力測積算無効電力量（遅れ）計測値（正方向、逆方向計測値）",
    [0xCC] = "積算無効電力量有効桁数",
    [0xCD] = "積算無効電力量単位",
    [0xCE] = "力測積算無効電力量（遅れ）計測値履歴（正方向計測値）",
    [0xCF] = "力測積算無効電力量（遅れ）計測値履歴（逆方向計測値）",
    [0xD0] = "1分積算有効電力量計測値（正方向、逆方向計測値）",
    [0xD1] = "1分力測積算無効電力量（遅れ）計測値（正方向、逆方向計測値）",
    [0xD3] = "係数",
    [0xD4] = "係数の倍率",
    [0xD5] = "積算無効電力量計測値（遅れ）現在値（正方向、逆方向計測値）",
    [0xD6] = "積算無効電力量計測値（進み）現在値（正方向、逆方向計測値）",
    [0xE0] = "確定日",
    [0xE1] = "積算履歴収集日",
    [0xE2] = "積算有効電力量計測値（正方向、逆方向計測値）",
    [0xE3] = "定時積算有効電力量計測値（正方向、逆方向計測値）",
    [0xE4] = "力測積算有効電力量計測値（正方向、逆方向計測値）",
    [0xE5] = "積算有効電力量有効桁数",
    [0xE6] = "積算有効電力量単位",
    [0xE7] = "積算有効電力量計測値履歴（正方向計測値）",
    [0xE8] = "積算有効電力量計測値履歴（逆方向計測値）",
    [0xEA] = "瞬時電力計測値",
    [0xEB] = "瞬時電流計測値２",
    [0xED] = "積算有効電力量計測値履歴２（正方向、逆方向計測値）",
    [0xEE] = "力測積算無効電力量（遅れ）計測値履歴２（正方向、逆方向計測値）",
    [0xEF] = "積算履歴収集日時２",
}

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

-- Parse datetime + forward + reverse energy (15 bytes)
-- Bytes 1-4: date YYYY:MM:DD, Bytes 5-7: time hh:mm:ss
-- Bytes 8-11: forward energy, Bytes 12-15: reverse energy
local function parse_datetime_fwd_rev(edttree, edt, fwd_label, rev_label)
    local year    = edt:range(0, 2):uint()
    local month   = edt:range(2, 1):uint()
    local day     = edt:range(3, 1):uint()
    local hour    = edt:range(4, 1):uint()
    local minute  = edt:range(5, 1):uint()
    local second  = edt:range(6, 1):uint()
    local forward = edt:range(7, 4):uint()
    local reverse = edt:range(11, 4):uint()
    edttree:add(edt:range(0, 4), string.format("計測年月日: %04d/%02d/%02d", year, month, day))
    edttree:add(edt:range(4, 3), string.format("計測時刻: %02d:%02d:%02d", hour, minute, second))
    local fwd_text = forward == 0xFFFFFFFE and "データなし" or string.format("%d", forward)
    local rev_text = reverse == 0xFFFFFFFE and "データなし" or string.format("%d", reverse)
    edttree:add(edt:range(7, 4), string.format("%s: %s", fwd_label, fwd_text))
    edttree:add(edt:range(11, 4), string.format("%s: %s", rev_label, rev_text))
    return year, month, day, hour, minute, second, forward, reverse
end

-- Parse history data (194 bytes: 2B collection day + 48 x 4B energy values)
local function parse_history48(edttree, edt, pdc)
    if pdc < 2 then return end
    local collection_day = edt:range(0, 2):uint()
    edttree:add(edt:range(0, 2), string.format("積算履歴収集日: %d (%s)",
        collection_day, collection_day == 0 and "当日" or string.format("%d日前", collection_day)))
    local count = math.floor((pdc - 2) / 4)
    for i = 0, count - 1 do
        local val = edt:range(2 + i * 4, 4):uint()
        local val_text = val == 0xFFFFFFFE and "データなし" or string.format("%d", val)
        edttree:add(edt:range(2 + i * 4, 4), string.format("[%02d:%02d] %s",
            math.floor(i / 2), (i % 2) * 30, val_text))
    end
    return collection_day, count
end

-- Parse history2 data (variable: 6B datetime + 1B count + n x 8B fwd/rev pairs, max 87 bytes)
local function parse_history2_fwd_rev(edttree, edt, pdc)
    if pdc < 7 then return end
    local year   = edt:range(0, 2):uint()
    local month  = edt:range(2, 1):uint()
    local day    = edt:range(3, 1):uint()
    local hour   = edt:range(4, 1):uint()
    local minute = edt:range(5, 1):uint()
    local count  = edt:range(6, 1):uint()
    edttree:add(edt:range(0, 6), string.format("積算履歴収集日時: %04d/%02d/%02d %02d:%02d",
        year, month, day, hour, minute))
    edttree:add(edt:range(6, 1), string.format("収集コマ数: %d", count))
    for i = 0, count - 1 do
        local offset = 7 + i * 8
        if offset + 8 > pdc then break end
        local forward = edt:range(offset, 4):uint()
        local reverse = edt:range(offset + 4, 4):uint()
        local fwd_text = forward == 0xFFFFFFFE and "データなし" or string.format("%d", forward)
        local rev_text = reverse == 0xFFFFFFFE and "データなし" or string.format("%d", reverse)
        edttree:add(edt:range(offset, 8),
            string.format("[%d] 正方向=%s 逆方向=%s", i + 1, fwd_text, rev_text))
    end
    return year, month, day, hour, minute, count
end

local function bidir_highvoltage_smart_meter(classgroup, class, epc, pdc, edt, tree, edata)
    if classgroup:uint() == 0x02 and class:uint() == 0x8F then
        local label = properties[epc:uint()]
        if not label then
            devicesuperclass(classgroup, class, epc, pdc, edt, tree, edata, properties)
            do return end
        end
        tree:add(edata.fields.epc, epc, epc:uint(), nil, string.format("(%s)", label))
        tree:add(edata.fields.pdc, pdc)
        tree:append_text(string.format(": %s", label))
        if pdc:uint() == 0 or edt:len() == 0 then
            do return end
        end

        local edttree = tree:add(edata.fields.edt, edt)

        if epc:uint() == 0xC0 then
            -- B-route identification number (16 bytes)
            if pdc:uint() ~= 16 then do return end end
            edttree:add(edt:range(0, 1), "通信ID:", string.format("0x%02x", edt:range(0, 1):uint()))
            edttree:add(edt:range(1, 3), "メーカコード:", tostring(edt:range(1, 3):bytes()))
            edttree:add(edt:range(4, 12), "自由領域:", tostring(edt:range(4, 12):bytes()))

        elseif epc:uint() == 0xD0 then
            -- 1-minute cumulative active energy (forward/reverse) (15 bytes)
            if pdc:uint() ~= 15 then do return end end
            local year, month, day, hour, minute, second, forward, reverse =
                parse_datetime_fwd_rev(edttree, edt, "積算有効電力量（正方向）", "積算有効電力量（逆方向）")
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d)",
                year, month, day, hour, minute, second, forward, reverse))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d",
                year, month, day, hour, minute, second, forward, reverse))

        elseif epc:uint() == 0xD1 then
            -- 1-minute power-measurement cumulative reactive energy (lag) (forward/reverse) (15 bytes)
            if pdc:uint() ~= 15 then do return end end
            local year, month, day, hour, minute, second, forward, reverse =
                parse_datetime_fwd_rev(edttree, edt, "積算無効電力量（遅れ）（正方向）", "積算無効電力量（遅れ）（逆方向）")
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d)",
                year, month, day, hour, minute, second, forward, reverse))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d",
                year, month, day, hour, minute, second, forward, reverse))

        elseif epc:uint() == 0xD3 then
            -- Coefficient (4 bytes, uint32, 0-999999)
            if pdc:uint() ~= 4 then do return end end
            edttree:append_text(string.format(" (%d)", edt:uint()))
            tree:append_text(string.format(" = %d", edt:uint()))

        elseif epc:uint() == 0xD4 then
            -- Coefficient multiplier (1 byte)
            if pdc:uint() ~= 1 then do return end end
            local multiplier_map = {
                [0x00] = "×1",
                [0x01] = "×0.1",
                [0x02] = "×0.01",
                [0x03] = "×0.001",
            }
            local m = multiplier_map[edt:uint()] or string.format("不明 (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", m))
            tree:append_text(string.format(" = %s", m))

        elseif epc:uint() == 0xE0 then
            -- Settlement date (1 byte, 1-31)
            if pdc:uint() ~= 1 then do return end end
            edttree:append_text(string.format(" (%d日)", edt:uint()))
            tree:append_text(string.format(" = %d日", edt:uint()))

        elseif epc:uint() == 0xE1 then
            -- Collection day for history (1 byte, 0-99)
            if pdc:uint() ~= 1 then do return end end
            local day = edt:uint()
            local text = day == 0 and "当日" or string.format("%d日前", day)
            edttree:append_text(string.format(" (%s)", text))
            tree:append_text(string.format(" = %s", text))

        elseif epc:uint() == 0xE2 or epc:uint() == 0xE3 or epc:uint() == 0xE4 then
            -- Cumulative active energy: measurement / fixed-time / power-measurement
            -- forward/reverse (15 bytes)
            if pdc:uint() ~= 15 then do return end end
            local year, month, day, hour, minute, second, forward, reverse =
                parse_datetime_fwd_rev(edttree, edt, "積算有効電力量（正方向）", "積算有効電力量（逆方向）")
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d)",
                year, month, day, hour, minute, second, forward, reverse))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d",
                year, month, day, hour, minute, second, forward, reverse))

        elseif epc:uint() == 0xE5 or epc:uint() == 0xC4 or epc:uint() == 0xCC then
            -- Effective digits (1 byte, 1-8)
            if pdc:uint() ~= 1 then do return end end
            edttree:append_text(string.format(" (%d桁)", edt:uint()))
            tree:append_text(string.format(" = %d桁", edt:uint()))

        elseif epc:uint() == 0xE6 then
            -- Unit of cumulative active energy (1 byte, kWh)
            if pdc:uint() ~= 1 then do return end end
            local unit_map = {
                [0x00] = "1 kWh",
                [0x01] = "0.1 kWh",
                [0x02] = "0.01 kWh",
                [0x03] = "0.001 kWh",
                [0x04] = "0.0001 kWh",
                [0x0A] = "10 kWh",
                [0x0B] = "100 kWh",
                [0x0C] = "1000 kWh",
                [0x0D] = "10000 kWh",
                [0x0E] = "100000 kWh",
            }
            local u = unit_map[edt:uint()] or string.format("不明 (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", u))
            tree:append_text(string.format(" = %s", u))

        elseif epc:uint() == 0xE7 or epc:uint() == 0xE8
            or epc:uint() == 0xC6 or epc:uint() == 0xC8
            or epc:uint() == 0xCE or epc:uint() == 0xCF then
            -- History (194 bytes: 2B day + 48 x 4B)
            local collection_day, count = parse_history48(edttree, edt, pdc:uint())
            if collection_day then
                edttree:append_text(string.format(" (収集日=%d, %dコマ)", collection_day, count))
                tree:append_text(string.format(" = 収集日=%d, %dコマ", collection_day, count))
            end

        elseif epc:uint() == 0xC1 or epc:uint() == 0xC2 then
            -- Monthly max / cumulative max demand power (forward/reverse) (8 bytes)
            if pdc:uint() ~= 8 then do return end end
            local forward = edt:range(0, 4):uint()
            local reverse = edt:range(4, 4):uint()
            edttree:add(edt:range(0, 4), string.format("正方向: %d", forward))
            edttree:add(edt:range(4, 4), string.format("逆方向: %d", reverse))
            edttree:append_text(string.format(" (正方向=%d 逆方向=%d)", forward, reverse))
            tree:append_text(string.format(" = 正方向=%d 逆方向=%d", forward, reverse))

        elseif epc:uint() == 0xC3 then
            -- Fixed-time demand power / 30-min avg (forward/reverse) (15 bytes)
            if pdc:uint() ~= 15 then do return end end
            local year, month, day, hour, minute, second, forward, reverse =
                parse_datetime_fwd_rev(edttree, edt, "需要電力（正方向）", "需要電力（逆方向）")
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d)",
                year, month, day, hour, minute, second, forward, reverse))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d",
                year, month, day, hour, minute, second, forward, reverse))

        elseif epc:uint() == 0xC5 or epc:uint() == 0xC7 then
            -- Unit of demand power / cumulative max demand power (1 byte, kW)
            if pdc:uint() ~= 1 then do return end end
            local unit_map = {
                [0x00] = "1 kW",
                [0x01] = "0.1 kW",
                [0x02] = "0.01 kW",
                [0x03] = "0.001 kW",
                [0x04] = "0.0001 kW",
                [0x0A] = "10 kW",
                [0x0B] = "100 kW",
                [0x0C] = "1000 kW",
                [0x0D] = "10000 kW",
                [0x0E] = "100000 kW",
            }
            local u = unit_map[edt:uint()] or string.format("不明 (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", u))
            tree:append_text(string.format(" = %s", u))

        elseif epc:uint() == 0xCA or epc:uint() == 0xCB
            or epc:uint() == 0xD5 or epc:uint() == 0xD6 then
            -- Power-measurement cumulative reactive energy (lag/lead): measurement / fixed-time
            -- forward/reverse (15 bytes)
            if pdc:uint() ~= 15 then do return end end
            local fwd_label = "積算無効電力量（正方向）"
            local rev_label = "積算無効電力量（逆方向）"
            local year, month, day, hour, minute, second, forward, reverse =
                parse_datetime_fwd_rev(edttree, edt, fwd_label, rev_label)
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d)",
                year, month, day, hour, minute, second, forward, reverse))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 正方向=%d 逆方向=%d",
                year, month, day, hour, minute, second, forward, reverse))

        elseif epc:uint() == 0xCD then
            -- Unit of reactive energy (lag) (1 byte, kvarh)
            if pdc:uint() ~= 1 then do return end end
            local unit_map = {
                [0x00] = "1 kvarh",
                [0x01] = "0.1 kvarh",
                [0x02] = "0.01 kvarh",
                [0x03] = "0.001 kvarh",
                [0x04] = "0.0001 kvarh",
                [0x0A] = "10 kvarh",
                [0x0B] = "100 kvarh",
                [0x0C] = "1000 kvarh",
                [0x0D] = "10000 kvarh",
                [0x0E] = "100000 kvarh",
            }
            local u = unit_map[edt:uint()] or string.format("不明 (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", u))
            tree:append_text(string.format(" = %s", u))

        elseif epc:uint() == 0xEA then
            -- Instantaneous power (4 bytes, signed int32, W)
            if pdc:uint() ~= 4 then do return end end
            local power = edt:int()
            edttree:append_text(string.format(" (%d W)", power))
            tree:append_text(string.format(" = %d W", power))

        elseif epc:uint() == 0xEB then
            -- Instantaneous current (8 bytes: 4B R-phase + 4B T-phase, signed int32, 0.1A)
            -- T-phase = 0x7FFFFFFE means single-phase 2-wire
            if pdc:uint() ~= 8 then do return end end
            local r_phase = edt:range(0, 4):int()
            local t_raw   = edt:range(4, 4):uint()
            local t_phase = edt:range(4, 4):int()
            edttree:add(edt:range(0, 4), string.format("R相: %.1f A", r_phase / 10.0))
            if t_raw == 0x7FFFFFFE then
                edttree:add(edt:range(4, 4), "T相: N/A（単相2線式）")
                edttree:append_text(string.format(" (R相=%.1f A, T相=N/A)", r_phase / 10.0))
                tree:append_text(string.format(" = R相=%.1f A, T相=N/A", r_phase / 10.0))
            else
                edttree:add(edt:range(4, 4), string.format("T相: %.1f A", t_phase / 10.0))
                edttree:append_text(string.format(" (R相=%.1f A, T相=%.1f A)", r_phase / 10.0, t_phase / 10.0))
                tree:append_text(string.format(" = R相=%.1f A, T相=%.1f A", r_phase / 10.0, t_phase / 10.0))
            end

        elseif epc:uint() == 0xED or epc:uint() == 0xEE then
            -- History 2: cumulative active energy / reactive energy (lag)
            -- forward/reverse, 1-minute interval, max 10 entries (max 87 bytes)
            local year, month, day, hour, minute, count =
                parse_history2_fwd_rev(edttree, edt, pdc:uint())
            if year then
                edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d, %dコマ)",
                    year, month, day, hour, minute, count))
                tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d, %dコマ",
                    year, month, day, hour, minute, count))
            end

        elseif epc:uint() == 0xEF then
            -- Collection date/time 2 (7 bytes: 6B datetime + 1B count)
            if pdc:uint() ~= 7 then do return end end
            local year   = edt:range(0, 2):uint()
            local month  = edt:range(2, 1):uint()
            local day    = edt:range(3, 1):uint()
            local hour   = edt:range(4, 1):uint()
            local minute = edt:range(5, 1):uint()
            local count  = edt:range(6, 1):uint()
            edttree:add(edt:range(0, 6), string.format("積算履歴収集日時: %04d/%02d/%02d %02d:%02d",
                year, month, day, hour, minute))
            edttree:add(edt:range(6, 1), string.format("収集コマ数: %d", count))
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d, 収集コマ数=%d)",
                year, month, day, hour, minute, count))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d, 収集コマ数=%d",
                year, month, day, hour, minute, count))
        end
    end
end

return bidir_highvoltage_smart_meter
