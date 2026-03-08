-- ########################################################
-- ECHONET Lite
-- Low Voltage Smart Electric Energy Meter Class
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
-- Low Voltage Smart Electric Energy Meter Class
--   Class group code : 0x02
--   Class code       : 0x88
--   Spec             : ECHONET Appendix Release R rev.4, Section 3.3.25
--
local devicesuperclass = require("device-superclass")
local list = require("echonet-lite-codelist")
local properties = {
    [0xC0] = "B-route identification number",
    [0xD0] = "1-minute cumulative energy (forward/reverse direction)",
    [0xD3] = "Coefficient",
    [0xD7] = "Effective digits of cumulative energy",
    [0xE0] = "Cumulative energy measurement (forward direction)",
    [0xE1] = "Unit of cumulative energy (forward/reverse direction)",
    [0xE2] = "Cumulative energy measurement history 1 (forward direction)",
    [0xE3] = "Cumulative energy measurement (reverse direction)",
    [0xE4] = "Cumulative energy measurement history 1 (reverse direction)",
    [0xE5] = "Day for which the historical data of cumulative energy is to be retrieved 1",
    [0xE7] = "Measured instantaneous power",
    [0xE8] = "Measured instantaneous current",
    [0xEA] = "Measured cumulative energy at fixed time (forward direction)",
    [0xEB] = "Measured cumulative energy at fixed time (reverse direction)",
    [0xEC] = "Cumulative energy measurement history 2 (forward/reverse direction)",
    [0xED] = "Day for which the historical data of cumulative energy is to be retrieved 2",
    [0xEE] = "Cumulative energy measurement history 3 (forward/reverse direction)",
    [0xEF] = "Day for which the historical data of cumulative energy is to be retrieved 3",
}

-- ========================================================
-- ECHONET Lite epc parser
-- ========================================================

local function lowvoltage_smart_meter(classgroup, class, epc, pdc, edt, tree, edata)
    if classgroup:uint() == 0x02 and class:uint() == 0x88 then
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
            -- Byte 1: communication ID, Bytes 2-4: manufacturer code, Bytes 5-16: free area
            if pdc:uint() ~= 16 then
                do return end
            end
            edttree:add(edt:range(0, 1), "Communication ID:", string.format("0x%02x", edt:range(0, 1):uint()))
            edttree:add(edt:range(1, 3), "Manufacturer code:", tostring(edt:range(1, 3):bytes()))
            edttree:add(edt:range(4, 12), "Free area:", tostring(edt:range(4, 12):bytes()))

        elseif epc:uint() == 0xD0 then
            -- 1-minute cumulative energy measurement (forward/reverse) (15 bytes)
            -- Bytes 1-4: date YYYY:MM:DD, Bytes 5-7: time hh:mm:ss
            -- Bytes 8-11: forward energy, Bytes 12-15: reverse energy
            if pdc:uint() ~= 15 then
                do return end
            end
            local year   = edt:range(0, 2):uint()
            local month  = edt:range(2, 1):uint()
            local day    = edt:range(3, 1):uint()
            local hour   = edt:range(4, 1):uint()
            local minute = edt:range(5, 1):uint()
            local second = edt:range(6, 1):uint()
            local forward = edt:range(7, 4):uint()
            local reverse = edt:range(11, 4):uint()
            edttree:add(edt:range(0, 4), string.format("Date: %04d/%02d/%02d", year, month, day))
            edttree:add(edt:range(4, 3), string.format("Time: %02d:%02d:%02d", hour, minute, second))
            edttree:add(edt:range(7, 4), string.format("Forward energy: %d", forward))
            edttree:add(edt:range(11, 4), string.format("Reverse energy: %d", reverse))
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d fwd=%d rev=%d)",
                year, month, day, hour, minute, second, forward, reverse))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d fwd=%d rev=%d",
                year, month, day, hour, minute, second, forward, reverse))

        elseif epc:uint() == 0xD3 then
            -- Coefficient (4 bytes, uint32, 0-999999)
            if pdc:uint() ~= 4 then
                do return end
            end
            edttree:append_text(string.format(" (%d)", edt:uint()))
            tree:append_text(string.format(" = %d", edt:uint()))

        elseif epc:uint() == 0xD7 then
            -- Effective digits of cumulative energy (1 byte, 1-8)
            if pdc:uint() ~= 1 then
                do return end
            end
            edttree:append_text(string.format(" (%d digits)", edt:uint()))
            tree:append_text(string.format(" = %d digits", edt:uint()))

        elseif epc:uint() == 0xE0 or epc:uint() == 0xE3 then
            -- Cumulative energy measurement forward/reverse (4 bytes, uint32)
            if pdc:uint() ~= 4 then
                do return end
            end
            edttree:append_text(string.format(" (%d)", edt:uint()))
            tree:append_text(string.format(" = %d", edt:uint()))

        elseif epc:uint() == 0xE1 then
            -- Unit of cumulative energy measurement (1 byte)
            if pdc:uint() ~= 1 then
                do return end
            end
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
            local u = unit_map[edt:uint()] or string.format("Unknown (0x%02x)", edt:uint())
            edttree:append_text(string.format(" (%s)", u))
            tree:append_text(string.format(" = %s", u))

        elseif epc:uint() == 0xE2 or epc:uint() == 0xE4 then
            -- Cumulative energy measurement history 1 forward/reverse
            -- 2 bytes: collection day, then 48 x 4 bytes: energy values (194 bytes total)
            if pdc:uint() < 2 then
                do return end
            end
            local collection_day = edt:range(0, 2):uint()
            edttree:add(edt:range(0, 2), string.format("Collection day: %d (%s)",
                collection_day, collection_day == 0 and "today" or string.format("%d day(s) ago", collection_day)))
            local count = math.floor((pdc:uint() - 2) / 4)
            for i = 0, count - 1 do
                local val = edt:range(2 + i * 4, 4):uint()
                local val_text
                if val == 0xFFFFFFFE then
                    val_text = "No data"
                else
                    val_text = string.format("%d", val)
                end
                edttree:add(edt:range(2 + i * 4, 4), string.format("[%02d:%02d] %s",
                    math.floor(i / 2), (i % 2) * 30, val_text))
            end
            edttree:append_text(string.format(" (day=%d, %d entries)", collection_day, count))
            tree:append_text(string.format(" = day=%d, %d entries", collection_day, count))

        elseif epc:uint() == 0xE5 then
            -- Day for which the historical data is to be retrieved 1 (1 byte, 0-99)
            if pdc:uint() ~= 1 then
                do return end
            end
            local day = edt:uint()
            local text = day == 0 and "Today" or string.format("%d day(s) ago", day)
            edttree:append_text(string.format(" (%s)", text))
            tree:append_text(string.format(" = %s", text))

        elseif epc:uint() == 0xE7 then
            -- Measured instantaneous power (4 bytes, signed int32, unit: W)
            if pdc:uint() ~= 4 then
                do return end
            end
            local power = edt:int()
            edttree:append_text(string.format(" (%d W)", power))
            tree:append_text(string.format(" = %d W", power))

        elseif epc:uint() == 0xE8 then
            -- Measured instantaneous current (4 bytes: 2B R-phase + 2B T-phase, unit: 0.1A)
            -- T-phase = 0x7FFE means single-phase 2-wire (no T-phase)
            if pdc:uint() ~= 4 then
                do return end
            end
            local r_phase = edt:range(0, 2):int()
            local t_raw   = edt:range(2, 2):uint()
            local t_phase = edt:range(2, 2):int()
            edttree:add(edt:range(0, 2), string.format("R-phase: %.1f A", r_phase / 10.0))
            if t_raw == 0x7FFE then
                edttree:add(edt:range(2, 2), "T-phase: N/A (single-phase 2-wire)")
                edttree:append_text(string.format(" (R=%.1f A, T=N/A)", r_phase / 10.0))
                tree:append_text(string.format(" = R=%.1f A, T=N/A", r_phase / 10.0))
            else
                edttree:add(edt:range(2, 2), string.format("T-phase: %.1f A", t_phase / 10.0))
                edttree:append_text(string.format(" (R=%.1f A, T=%.1f A)", r_phase / 10.0, t_phase / 10.0))
                tree:append_text(string.format(" = R=%.1f A, T=%.1f A", r_phase / 10.0, t_phase / 10.0))
            end

        elseif epc:uint() == 0xEA or epc:uint() == 0xEB then
            -- Measured cumulative energy at fixed time forward/reverse (11 bytes)
            -- Bytes 1-4: date YYYY:MM:DD, Bytes 5-7: time hh:mm:ss, Bytes 8-11: energy
            if pdc:uint() ~= 11 then
                do return end
            end
            local year   = edt:range(0, 2):uint()
            local month  = edt:range(2, 1):uint()
            local day    = edt:range(3, 1):uint()
            local hour   = edt:range(4, 1):uint()
            local minute = edt:range(5, 1):uint()
            local second = edt:range(6, 1):uint()
            local energy = edt:range(7, 4):uint()
            edttree:add(edt:range(0, 4), string.format("Date: %04d/%02d/%02d", year, month, day))
            edttree:add(edt:range(4, 3), string.format("Time: %02d:%02d:%02d", hour, minute, second))
            edttree:add(edt:range(7, 4), string.format("Energy: %d", energy))
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d:%02d energy=%d)",
                year, month, day, hour, minute, second, energy))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d:%02d energy=%d",
                year, month, day, hour, minute, second, energy))

        elseif epc:uint() == 0xEC or epc:uint() == 0xEE then
            -- Cumulative energy measurement history 2 (30-min intervals, max 103 bytes) /
            -- history 3 (1-min intervals, max 87 bytes)
            -- Bytes 1-6: collection datetime YYYY:MM:DD:hh:mm
            -- Byte 7: count of entries (max 12 for 0xEC, max 10 for 0xEE)
            -- Bytes 8+: pairs of forward/reverse energy (4+4 bytes each)
            if pdc:uint() < 7 then
                do return end
            end
            local year   = edt:range(0, 2):uint()
            local month  = edt:range(2, 1):uint()
            local day    = edt:range(3, 1):uint()
            local hour   = edt:range(4, 1):uint()
            local minute = edt:range(5, 1):uint()
            local count  = edt:range(6, 1):uint()
            edttree:add(edt:range(0, 6), string.format("Collection datetime: %04d/%02d/%02d %02d:%02d",
                year, month, day, hour, minute))
            edttree:add(edt:range(6, 1), string.format("Count: %d", count))
            for i = 0, count - 1 do
                local offset = 7 + i * 8
                if offset + 8 > pdc:uint() then break end
                local forward = edt:range(offset, 4):uint()
                local reverse = edt:range(offset + 4, 4):uint()
                local fwd_text = forward == 0xFFFFFFFE and "No data" or string.format("%d", forward)
                local rev_text = reverse == 0xFFFFFFFE and "No data" or string.format("%d", reverse)
                edttree:add(edt:range(offset, 8),
                    string.format("[%d] fwd=%s rev=%s", i + 1, fwd_text, rev_text))
            end
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d, %d entries)",
                year, month, day, hour, minute, count))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d, %d entries",
                year, month, day, hour, minute, count))

        elseif epc:uint() == 0xED or epc:uint() == 0xEF then
            -- Day for which the historical data is to be retrieved 2/3
            -- 7 bytes: 6B datetime (YYYY:MM:DD:hh:mm) + 1B count
            if pdc:uint() ~= 7 then
                do return end
            end
            local year   = edt:range(0, 2):uint()
            local month  = edt:range(2, 1):uint()
            local day    = edt:range(3, 1):uint()
            local hour   = edt:range(4, 1):uint()
            local minute = edt:range(5, 1):uint()
            local count  = edt:range(6, 1):uint()
            edttree:add(edt:range(0, 6), string.format("Datetime: %04d/%02d/%02d %02d:%02d",
                year, month, day, hour, minute))
            edttree:add(edt:range(6, 1), string.format("Count: %d", count))
            edttree:append_text(string.format(" (%04d/%02d/%02d %02d:%02d, count=%d)",
                year, month, day, hour, minute, count))
            tree:append_text(string.format(" = %04d/%02d/%02d %02d:%02d, count=%d",
                year, month, day, hour, minute, count))
        end
    end
end

return lowvoltage_smart_meter
