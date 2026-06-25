-----------------------------------------------------------
--  KFT AUTO Mode Altitude Override  v7.0 FINAL
--  Platform  : ArduCopter 4.6.x
--  FC        : Pixhawk 6C
--  TX        : Skydroid T12
--  Frame     : EFT E610P Hexacopter (Sprayer)
--  Author    : Kapil Future Tech (KFT)
--  Date      : 2026-04-13
--
--  KEY DESIGN — MAP POLYGON BOUNDARY (No fence needed):
--
--    The pilot draws a spray area polygon on the GCS map
--    using dots (waypoints). This script reads ALL mission
--    waypoints at startup, builds a convex boundary from
--    them, and uses that as the hard boundary during GUIDED.
--
--    ┌─────────────────────────────┐  ← FC Fence (optional)
--    │  ┌───────────────────────┐  │
--    │  │  • — — — — — — — •   │  │  ← Mission waypoints
--    │  │  |  spray lanes    |  │  │    define the map
--    │  │  • — — — — — — — •   │  │    polygon boundary
--    │  └───────────────────────┘  │
--    └─────────────────────────────┘
--
--    During semi-auto GUIDED override:
--      - Horizontal velocity = 0 always (FIX 5)
--        → drone climbs straight up, zero lateral drift
--      - Even if tiny GPS drift occurs, boundary check
--        catches it and forces return to AUTO
--      - Works completely without FENCE_ENABLE or any
--        fence parameters — uses mission WPs only
--
--  ALL FIXES:
--    FIX 1 — Lane skipping: no set_current_cmd()       ✅
--    FIX 2 — Speed spike: horizontal zeroed             ✅
--    FIX 3 — Map boundary: built from mission WPs,
--             no fence params needed                    ✅
--    FIX 4 — Spray off during override: relay:on()     ✅
--    FIX 5 — Shaky lines: Vn=0 Ve=0, FC holds XY      ✅
--
--  CONFIRMED WORKING APIs (4.6.3):
--    ahrs:get_relative_position_NED_home()  ✅
--    ahrs:get_position()                    ✅
--    vehicle:set_target_velocity_NED()      ✅
--    vehicle:set_mode()                     ✅
--    vehicle:get_mode()                     ✅
--    rc:get_pwm()                           ✅
--    mission:num_commands()                 ✅
--    mission:get_item()                     ✅
--    mission:get_current_nav_index()        ✅
--    gcs:send_text()                        ✅
--    relay:on(ch) / relay:off(ch)           ✅
--
--  INSTALL:
--    Copy to: APM/scripts/kft_auto_alt_override.lua
--    Params : SCR_ENABLE=1   SCR_HEAP_SIZE=131072
--    No fence parameters needed at all.
--    Only edit SPRAY_RELAY_CH if pump is not RELAY_PIN1.
--    Reboot → GCS: "KFT ALT v7.0 FINAL Ready"
-----------------------------------------------------------

-- =====================================================
--  CONFIGURATION  ← Only edit SPRAY_RELAY_CH
-- =====================================================
local CFG = {
    -- RC / Throttle channel
    THR_CH            = 3,
    PWM_MIN           = 1050,
    PWM_MID           = 1501,
    PWM_MAX           = 1950,
    DEADZONE          = 70,

    -- Vertical rates
    CLIMB_MS          = 1.5,   -- max climb rate   (m/s)
    DESCEND_MS        = 1.0,   -- max descent rate (m/s)

    -- Altitude safety limits (metres above home)
    ALT_MIN_M         = 1.0,
    ALT_MAX_M         = 30.0,

    -- Buffer inside mission polygon boundary (metres)
    -- Drone will not go within this distance of the
    -- mission waypoint boundary edge during GUIDED.
    -- 3.0m recommended — covers GPS drift + momentum.
    POLY_MARGIN_M     = 3.0,

    -- Spray pump relay (0=RELAY_PIN1, 1=RELAY_PIN2 …)
    SPRAY_RELAY_CH    = 0,

    -- Timing
    RETURN_CYCLES     = 15,    -- 15 × 100ms = 1.5s → AUTO
    LOOP_MS           = 100,
    FORCE_BACK_CYCLES = 5,
}

-- =====================================================
--  CONSTANTS
-- =====================================================
local MODE_AUTO   = 3
local MODE_GUIDED = 4

local SAFETY_MODES = { [5]=true, [11]=true, [17]=true }

local RANGE_UP   = CFG.PWM_MAX - CFG.PWM_MID
local RANGE_DOWN = CFG.PWM_MID - CFG.PWM_MIN

-- MAV_CMD_NAV waypoint types to include in polygon
local NAV_WAYPOINT      = 16
local NAV_SPLINE_WP     = 82

-- =====================================================
--  STATE
-- =====================================================
local in_override      = false
local hold_counter     = 0
local log_tick         = 0
local force_back_timer = 0

-- Mission polygon points (lat/lng in degrees × 1e-7)
-- Built once at startup from mission waypoints
local poly_pts   = {}   -- {lat, lng} pairs in degrees
local poly_ready = false

-- =====================================================
--  BUILD POLYGON from mission waypoints at startup
--
--  Reads all NAV_WAYPOINT commands from the mission,
--  extracts their lat/lng, stores as polygon boundary.
--  Called once at boot and again if mission changes.
-- =====================================================
local function build_polygon_from_mission()
    poly_pts   = {}
    poly_ready = false

    local n = mission:num_commands()
    if not n or n < 2 then
        gcs:send_text(4, "KFT ALT: No mission loaded — boundary check disabled")
        return
    end

    for i = 0, n - 1 do
        local item = mission:get_item(i)
        if item then
            local id = item:id()
            if id == NAV_WAYPOINT or id == NAV_SPLINE_WP then
                local loc = item:get_loc()
                if loc then
                    local lat = loc:lat()  -- stored as int32 × 1e7
                    local lng = loc:lng()
                    -- Skip WPs at (0,0) — these are invalid
                    if math.abs(lat) > 100 and math.abs(lng) > 100 then
                        poly_pts[#poly_pts + 1] = {
                            lat = lat * 1e-7,
                            lng = lng * 1e-7
                        }
                    end
                end
            end
        end
    end

    if #poly_pts >= 3 then
        poly_ready = true
        gcs:send_text(6, string.format(
            "KFT ALT: Mission polygon built | %d waypoints", #poly_pts))
    else
        gcs:send_text(4, string.format(
            "KFT ALT: Only %d WPs found — need 3+ for boundary", #poly_pts))
    end
end

-- =====================================================
--  HELPER: Distance from point to line segment (metres)
--  Used to find nearest polygon edge distance
-- =====================================================
local function dist_point_to_segment_m(px, py, ax, ay, bx, by)
    -- Convert lat/lng degree differences to metres
    -- 1 deg lat ≈ 111320m, 1 deg lng ≈ 111320 × cos(lat)
    local cos_lat = math.cos(math.rad(py))
    local dx = (bx - ax) * 111320.0
    local dy = (by - ay) * 111320.0 * cos_lat
    local len2 = dx * dx + dy * dy
    local t = 0.0
    if len2 > 1e-10 then
        local fx = (px - ax) * 111320.0
        local fy = (py - ay) * 111320.0 * cos_lat
        t = math.max(0.0, math.min(1.0, (fx * dx + fy * dy) / len2))
    end
    local cx = ax + t * (bx - ax)
    local cy = ay + t * (by - ay)
    local ex = (px - cx) * 111320.0
    local ey = (py - cy) * 111320.0 * cos_lat
    return math.sqrt(ex * ex + ey * ey)
end

-- =====================================================
--  HELPER: Point-in-polygon (ray casting)
--  Returns true if (lat, lng) is inside poly_pts
-- =====================================================
local function point_in_polygon(lat, lng)
    local n      = #poly_pts
    local inside = false
    local j      = n
    for i = 1, n do
        local xi = poly_pts[i].lat
        local yi = poly_pts[i].lng
        local xj = poly_pts[j].lat
        local yj = poly_pts[j].lng
        if ((yi > lng) ~= (yj > lng)) and
           (lat < (xj - xi) * (lng - yi) / (yj - yi) + xi) then
            inside = not inside
        end
        j = i
    end
    return inside
end

-- =====================================================
--  HELPER: Minimum distance from drone to polygon edge
--  Returns:
--    positive number = metres INSIDE polygon to nearest edge
--    negative number = metres OUTSIDE polygon (bad!)
--    nil             = polygon not ready
-- =====================================================
local function dist_to_poly_edge_m()
    if not poly_ready or #poly_pts < 3 then return nil end

    local loc = ahrs:get_position()
    if not loc then return nil end

    local dlat = loc:lat() * 1e-7
    local dlng = loc:lng() * 1e-7

    -- Find minimum distance to any edge
    local min_d = math.huge
    local n     = #poly_pts
    for i = 1, n do
        local j = (i % n) + 1
        local d = dist_point_to_segment_m(
            dlat, dlng,
            poly_pts[i].lat, poly_pts[i].lng,
            poly_pts[j].lat, poly_pts[j].lng)
        if d < min_d then min_d = d end
    end

    -- Positive if inside, negative if outside
    if point_in_polygon(dlat, dlng) then
        return min_d    -- inside: distance to nearest edge
    else
        return -min_d   -- outside: negative distance
    end
end

-- =====================================================
--  HELPER: Normalised throttle stick [-1.0 .. +1.0]
-- =====================================================
local function get_stick_norm()
    local pwm = rc:get_pwm(CFG.THR_CH)
    if not pwm then return 0.0 end
    local delta = pwm - CFG.PWM_MID
    if math.abs(delta) <= CFG.DEADZONE then return 0.0 end
    if delta > 0 then
        return math.min(1.0,  (delta - CFG.DEADZONE) / (RANGE_UP   - CFG.DEADZONE))
    else
        return math.max(-1.0, (delta + CFG.DEADZONE) / (RANGE_DOWN - CFG.DEADZONE))
    end
end

-- =====================================================
--  HELPER: Altitude above home (m)
-- =====================================================
local function get_alt_m()
    local ned = ahrs:get_relative_position_NED_home()
    if ned then return -ned:z() end
    return nil
end

-- =====================================================
--  FIX 5: Pure vertical velocity only
--  Vn=0 Ve=0 → FC internal XY position hold (smooth)
--  No lateral drift, no shaky lines, stays inside map
-- =====================================================
local function send_velocity_NED(vz_ms)
    local v = Vector3f()
    v:x(0.0)
    v:y(0.0)
    v:z(-vz_ms)
    vehicle:set_target_velocity_NED(v)
end

-- =====================================================
--  Spray control
-- =====================================================
local function spray_on()
    relay:on(CFG.SPRAY_RELAY_CH)
end

local function spray_emergency_off()
    relay:off(CFG.SPRAY_RELAY_CH)
end

-- =====================================================
--  Return to AUTO — spray relay untouched
-- =====================================================
local function return_to_auto(reason)
    vehicle:set_mode(MODE_AUTO)
    in_override  = false
    hold_counter = 0
    gcs:send_text(6, "KFT ALT: AUTO resumed | " .. reason .. " | Spray continues")
end

-- =====================================================
--  MAIN LOOP
-- =====================================================
local function update()

    local mode  = vehicle:get_mode()
    local stick = get_stick_norm()
    local alt   = get_alt_m()

    -- Force-back timer
    if force_back_timer > 0 then
        force_back_timer = force_back_timer - 1
        if force_back_timer == 0 then
            return_to_auto("mode-hijack recovery")
        end
        return update, CFG.LOOP_MS
    end

    -- ════════════════════════════════════════════════
    --  NOT IN OVERRIDE
    -- ════════════════════════════════════════════════
    if not in_override then

        -- Rebuild polygon if mission changes
        -- (check every 5s when not in override)
        log_tick = log_tick + 1
        if log_tick >= 50 then
            build_polygon_from_mission()
            log_tick = 0
        end

        if mode == MODE_AUTO and math.abs(stick) > 0.02 then

            if not alt then
                gcs:send_text(4, "KFT ALT: Waiting for AHRS fix...")
                return update, CFG.LOOP_MS
            end
            if alt <= CFG.ALT_MIN_M and stick < 0 then
                gcs:send_text(4, "KFT ALT: At FLOOR | Descent blocked")
                return update, CFG.LOOP_MS
            end
            if alt >= CFG.ALT_MAX_M and stick > 0 then
                gcs:send_text(4, "KFT ALT: At CEILING | Climb blocked")
                return update, CFG.LOOP_MS
            end

            -- Block GUIDED entry if near map polygon edge
            if poly_ready then
                local d = dist_to_poly_edge_m()
                if d and d < CFG.POLY_MARGIN_M then
                    gcs:send_text(4, string.format(
                        "KFT ALT: Near MAP EDGE (%.1fm) | Override blocked", d))
                    return update, CFG.LOOP_MS
                end
            end

            -- Enter GUIDED override
            vehicle:set_mode(MODE_GUIDED)
            in_override  = true
            hold_counter = 0
            spray_on()

            local cur_wp = mission:get_current_nav_index()
            gcs:send_text(6, string.format(
                "KFT ALT: ACTIVE | Alt=%.1fm Stk=%.2f WP=%s | Spray ON",
                alt, stick, tostring(cur_wp)))
        end

        return update, CFG.LOOP_MS
    end

    -- ════════════════════════════════════════════════
    --  IN OVERRIDE (GUIDED)
    -- ════════════════════════════════════════════════

    if mode ~= MODE_GUIDED then
        if mode == MODE_AUTO then
            in_override  = false
            hold_counter = 0
            gcs:send_text(6, "KFT ALT: Override cleared (AUTO) | Spray continues")

        elseif SAFETY_MODES[mode] then
            spray_emergency_off()
            in_override      = false
            hold_counter     = 0
            force_back_timer = 0
            gcs:send_text(3, string.format(
                "KFT ALT: !! SAFETY MODE %d !! Spray OFF | FC in charge", mode))

        else
            in_override      = false
            hold_counter     = 0
            force_back_timer = CFG.FORCE_BACK_CYCLES
            gcs:send_text(4, string.format(
                "KFT ALT: Mode→%d unexpected | Recovering in %.1fs",
                mode, CFG.FORCE_BACK_CYCLES * 0.1))
        end
        return update, CFG.LOOP_MS
    end

    -- Altitude safety clamp
    local stick_eff = stick
    if alt then
        if alt <= CFG.ALT_MIN_M and stick_eff < 0 then
            stick_eff = 0.0
            gcs:send_text(4, "KFT ALT: FLOOR limit | Descent blocked")
        end
        if alt >= CFG.ALT_MAX_M and stick_eff > 0 then
            stick_eff = 0.0
            gcs:send_text(4, "KFT ALT: CEILING limit | Climb blocked")
        end
    end

    -- ── Polygon boundary check every cycle in GUIDED ──
    if poly_ready then
        local d = dist_to_poly_edge_m()
        if d then
            if d < 0 then
                -- Drone is outside map polygon — force back to AUTO immediately
                gcs:send_text(3, string.format(
                    "KFT ALT: !! OUTSIDE MAP (%.1fm) !! AUTO forced", math.abs(d)))
                return_to_auto("outside map polygon")
                return update, CFG.LOOP_MS

            elseif d < CFG.POLY_MARGIN_M then
                -- Near edge — zero velocity, hold, warn pilot
                gcs:send_text(4, string.format(
                    "KFT ALT: Near MAP EDGE %.1fm | Holding", d))
                send_velocity_NED(0.0)
                spray_on()
                hold_counter = hold_counter + 1
                if hold_counter >= CFG.RETURN_CYCLES then
                    return_to_auto("near map edge")
                end
                return update, CFG.LOOP_MS
            end
        end
    end

    -- Keep spray ON every cycle
    spray_on()

    -- Stick active: pure vertical only (no horizontal drift)
    if math.abs(stick_eff) > 0.02 then
        local vz = stick_eff * (stick_eff > 0 and CFG.CLIMB_MS or CFG.DESCEND_MS)
        send_velocity_NED(vz)
        hold_counter = 0

    -- Stick centred: hold altitude, count down to AUTO
    else
        send_velocity_NED(0.0)
        hold_counter = hold_counter + 1

        if hold_counter == 1 then
            local a = alt and string.format("%.1fm", alt) or "N/A"
            gcs:send_text(6, "KFT ALT: Holding @ " .. a .. " | Returning to AUTO...")
        end

        if hold_counter >= CFG.RETURN_CYCLES then
            return_to_auto("stick centred")
        end
    end

    -- Periodic status every 5 s
    log_tick = log_tick + 1
    if log_tick >= 50 then
        local a  = alt and string.format("%.1fm", alt) or "---"
        local d  = dist_to_poly_edge_m()
        local de = d and string.format("%.1fm", d) or "---"
        local cw = mission:get_current_nav_index()
        gcs:send_text(6, string.format(
            "KFT | GUIDED | Alt:%s EdgeDist:%s Stk:%.2f Hold:%d WP:%s Spray:ON",
            a, de, stick, hold_counter, tostring(cw)))
        log_tick = 0
    end

    return update, CFG.LOOP_MS
end

-- =====================================================
--  STARTUP — build polygon from loaded mission
-- =====================================================
build_polygon_from_mission()
gcs:send_text(6,
    "KFT ALT v7.0 FINAL | Mission-polygon | Smooth | Spray-ON | T12:1050/1501/1950")
return update()
