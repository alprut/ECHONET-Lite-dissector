-- ########################################################
-- ECHONET Lite
-- High Voltage Smart Electric Energy Meter Class
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
-- High Voltage Smart Electric Energy Meter Class
--   Class group code : 0x02
--   Class code       : 0x8A
--   Spec             : ECHONET Appendix Release R rev.4, Section 3.3.27
--
local devicesuperclass = require("device-superclass")
local list = require("echonet-lite-codelist")
local properties = {
    [0xC1] = "月間最大需要電力",
    [0xC2] = "累積最大需要電力",
    [0xC3] = "定時需要電力（30分平均電力）",
    [0xC4] = "需要電力有効桁数",
    [0xC5] = "需要電力単位",
    [0xC6] = "需要電力計測値履歴",
    [0xC7] = "累積最大需要電力単位",
    [0xCA] = "力測積算無効電力量（遅れ）計測値",
    [0xCB] = "定時力測積算無効電力量（遅れ）計測値",
    [0xCC] = "力測積算無効電力量（遅れ）有効桁数",
    [0xCD] = "力測積算無効電力量（遅れ）単位",
    [0xCE] = "力測積算無効電力量（遅れ）計測値履歴",
    [0xD3] = "係数",
    [0xD4] = "係数の倍率",
    [0xE0] = "確定日",
    [0xE1] = "積算履歴収集日",
    [0xE2] = "積算有効電力量計測値",
    [0xE3] = "定時積算有効電力量計測値",
    [0xE4] = "力測積算有効電力量計測値",
    [0xE5] = "積算有効電力量有効桁数",
    [0xE6] = "積算有効電力量単位",
    [0xE7] = "積算有効電力量計測値履歴",
}

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

-- Parse datetime + energy value (11 bytes: YYYY 2B + MM:DD 2B + hh:mm:ss 3B + energy 4B)
local function parse_datetime_energy(edttree, edt, energy_label)
    local year   = edt:range(0, 2):uint()
    local month  = edt:range(2, 1):uint()
    local day    = edt:range(3, 1):uint()
    local hour   = edt:range(4, 1):uint()
    local minute = edt:range(5, 1):uint()
    local second = edt:range(6, 1):uint()
    local energy = edt:range(7, 4):uint()
    edttree:add(edt:range(0, 4), string.format("計測年月日: %04d/%02d/%02d", year, month, day))
    edttree:add(edt:range(4, 3), string.format("計測時刻: %02d:%02d:%02d", hour, minute, second))
    edttree:add(edt:range(7, 4), string.format("%s: %d", energy_label, energy))
    return year, month, day, hour, minute, second, energy
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

local function highvoltage_smart_meter(classgroup, class, epc, pdc, edt, tree, edata)
    if classgroup:uint() == 0x02 and class:uint() == 0x8A then
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

        if epc:uint() == 0xD3 then
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
            -- Cumulative active energy: measurement / fixed-time / power-measurement (11 bytes)
            if pdc:uint() ~= 11 then do return end end
            local year, month, day, hour, minute, second, energy =
                parse_datetime_energy(edttree, edt, "積算有効電力量")
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 積算有効電力量=%d)",
                year, month, day, hour, minute, second, energy))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 積算有効電力量=%d",
                year, month, day, hour, minute, second, energy))

        elseif epc:uint() == 0xE5 or epc:uint() == 0xC4 or epc:uint() == 0xCC then
            -- Effective digits (1 byte, 1-8): active energy / demand power / reactive energy
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
            }
            local u = unit_map[edt:uint()] or string.format("不明 (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", u))
            tree:append_text(string.format(" = %s", u))

        elseif epc:uint() == 0xE7 then
            -- History of cumulative active energy (194 bytes: 2B day + 48 x 4B)
            local collection_day, count = parse_history48(edttree, edt, pdc:uint())
            if collection_day then
                edttree:append_text(string.format(" (収集日=%d, %dコマ)", collection_day, count))
                tree:append_text(string.format(" = 収集日=%d, %dコマ", collection_day, count))
            end

        elseif epc:uint() == 0xC1 or epc:uint() == 0xC2 then
            -- Monthly max demand power / cumulative max demand power (4 bytes, uint32)
            if pdc:uint() ~= 4 then do return end end
            edttree:append_text(string.format(" (%d)", edt:uint()))
            tree:append_text(string.format(" = %d", edt:uint()))

        elseif epc:uint() == 0xC3 then
            -- Fixed-time demand power / 30-min avg (11 bytes)
            if pdc:uint() ~= 11 then do return end end
            local year, month, day, hour, minute, second, energy =
                parse_datetime_energy(edttree, edt, "需要電力")
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 需要電力=%d)",
                year, month, day, hour, minute, second, energy))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 需要電力=%d",
                year, month, day, hour, minute, second, energy))

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
            }
            local u = unit_map[edt:uint()] or string.format("不明 (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", u))
            tree:append_text(string.format(" = %s", u))

        elseif epc:uint() == 0xC6 then
            -- History of demand power (194 bytes: 2B day + 48 x 4B)
            local collection_day, count = parse_history48(edttree, edt, pdc:uint())
            if collection_day then
                edttree:append_text(string.format(" (収集日=%d, %dコマ)", collection_day, count))
                tree:append_text(string.format(" = 収集日=%d, %dコマ", collection_day, count))
            end

        elseif epc:uint() == 0xCA or epc:uint() == 0xCB then
            -- Power-measurement cumulative reactive energy (lag): measurement / fixed-time (11 bytes)
            if pdc:uint() ~= 11 then do return end end
            local year, month, day, hour, minute, second, energy =
                parse_datetime_energy(edttree, edt, "積算無効電力量（遅れ）")
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d 積算無効電力量（遅れ）=%d)",
                year, month, day, hour, minute, second, energy))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d 積算無効電力量（遅れ）=%d",
                year, month, day, hour, minute, second, energy))

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
            }
            local u = unit_map[edt:uint()] or string.format("不明 (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", u))
            tree:append_text(string.format(" = %s", u))

        elseif epc:uint() == 0xCE then
            -- History of reactive energy (lag) (194 bytes: 2B day + 48 x 4B)
            local collection_day, count = parse_history48(edttree, edt, pdc:uint())
            if collection_day then
                edttree:append_text(string.format(" (収集日=%d, %dコマ)", collection_day, count))
                tree:append_text(string.format(" = 収集日=%d, %dコマ", collection_day, count))
            end
        end
    end
end

return highvoltage_smart_meter
