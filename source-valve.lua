-- Protocol
local source_proto = Proto("SourceQuery", "Valve Source Engine Query")

-- General Protocol Fields
local f_header      = ProtoField.int32("sourcequery.header", "Connection Header", base.DEC)
local f_type        = ProtoField.uint8("sourcequery.type", "Response Type", base.HEX)

-- A2S_INFO Fields
local f_protocol    = ProtoField.uint8("sourcequery.protocol", "Network Protocol Version", base.DEC)
local f_name        = ProtoField.string("sourcequery.name", "Server Name")
local f_map         = ProtoField.string("sourcequery.map", "Map")
local f_folder      = ProtoField.string("sourcequery.folder", "Folder")
local f_game        = ProtoField.string("sourcequery.game", "Game")
local f_app_id      = ProtoField.uint16("sourcequery.appid", "App ID", base.DEC)
local f_players     = ProtoField.uint8("sourcequery.players", "Players", base.DEC)
local f_max_players = ProtoField.uint8("sourcequery.max_players", "Max Players", base.DEC)
local f_bots        = ProtoField.uint8("sourcequery.bots", "Bots", base.DEC)
local f_server_type = ProtoField.string("sourcequery.server_type", "Server Type")
local f_environment = ProtoField.uint8("sourcequery.environment", "Environment", base.DEC)
local f_visibility  = ProtoField.uint8("sourcequery.visibility", "Visibility", base.DEC)
local f_anticheat   = ProtoField.uint8("sourcequery.secure", "VAC Enabled", base.DEC)

-- A2S_PLAYER Fields
local f_player_count = ProtoField.uint8("sourcequery.player_count", "Player Count", base.DEC)
local f_p_index      = ProtoField.uint8("sourcequery.player.index", "Player Index", base.DEC)
local f_p_name       = ProtoField.string("sourcequery.player.name", "Player Name")
local f_p_score      = ProtoField.int32("sourcequery.player.score", "Score", base.DEC)
local f_p_duration   = ProtoField.float("sourcequery.player.duration", "Duration (s)", base.DEC)

source_proto.fields = {
    f_header, f_type,
    f_protocol, f_name, f_map, f_folder, f_game, f_app_id, f_players, f_max_players, f_bots, f_server_type, f_environment, f_visibility, f_anticheat,
    f_player_count, f_p_index, f_p_name, f_p_score, f_p_duration
}

-- Helper function to read null-terminated C-Strings
local function read_string(buffer, offset)
    local len = 0
    while offset + len < buffer:len() and buffer(offset + len, 1):uint() ~= 0 do
        len = len + 1
    end
    return buffer(offset, len):string(), offset + len + 1
end

function source_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 5 then return end

    local header = buffer(0, 4):le_int()
    if header ~= -1 then return end

    local resp_type = buffer(4, 1):uint()

    pinfo.cols.protocol = source_proto.name

    local subtree = tree:add(source_proto, buffer(), "Valve Source Engine Query")
    subtree:add(f_header, buffer(0, 4))
    subtree:add(f_type, buffer(4, 1))

    local offset = 5

    ----------------------------------------------------------------------------
    -- A2S_INFO Response (Header: 'I' / 0x49)
    ----------------------------------------------------------------------------
    if resp_type == 0x49 then

        subtree:add(f_protocol, buffer(offset, 1))
        offset = offset + 1

        local name, next_offset = read_string(buffer, offset)
        pinfo.cols.info = string.format("A2S_INFO Response - %s", name)
        subtree:add(f_name, buffer(offset, next_offset - offset - 1))
        offset = next_offset

        local map
        map, next_offset = read_string(buffer, offset)
        subtree:add(f_map, buffer(offset, next_offset - offset - 1))
        offset = next_offset

        local folder
        folder, next_offset = read_string(buffer, offset)
        subtree:add(f_folder, buffer(offset, next_offset - offset - 1))
        offset = next_offset

        local game
        game, next_offset = read_string(buffer, offset)
        subtree:add(f_game, buffer(offset, next_offset - offset - 1))
        offset = next_offset

        subtree:add_le(f_app_id, buffer(offset, 2))
        offset = offset + 2

        subtree:add(f_players, buffer(offset, 1))
        subtree:add(f_max_players, buffer(offset + 1, 1))
        subtree:add(f_bots, buffer(offset + 2, 1))

    ----------------------------------------------------------------------------
    -- A2S_PLAYER Response (Header: 'D' / 0x44)
    ----------------------------------------------------------------------------
    elseif resp_type == 0x44 then
        local count = buffer(offset, 1):uint()
        pinfo.cols.info = string.format("A2S_PLAYER Response (%d players)", count)

        subtree:add(f_player_count, buffer(offset, 1))
        offset = offset + 1

        for i = 1, count do
            -- Break early if buffer truncated
            if offset >= buffer:len() then break end

            local p_index = buffer(offset, 1):uint()
            local p_name, next_offset = read_string(buffer, offset + 1)

            -- Ensure buffer has enough remaining bytes for Score (4) + Duration (4)
            if next_offset + 8 > buffer:len() then break end

            local p_score = buffer(next_offset, 4):le_int()
            local p_duration = buffer(next_offset + 4, 4):le_float()

            -- Nested subtree for each player
            local player_tree = subtree:add(
                source_proto,
                buffer(offset, (next_offset + 8) - offset),
                string.format("Player %d: %s", i, p_name ~= "" and p_name or "<Connecting...>")
            )

            player_tree:add(f_p_index, buffer(offset, 1))
            player_tree:add(f_p_name, buffer(offset + 1, next_offset - offset - 2))
            player_tree:add_le(f_p_score, buffer(next_offset, 4))
            player_tree:add_le(f_p_duration, buffer(next_offset + 4, 4))

            offset = next_offset + 8
        end
    else
        if resp_type == 0x54 then
            pinfo.cols.info = string.format("Source Query A2S_INFO_REQUEST: 0x%02X", resp_type)
        elseif resp_type == 0x41 then
            pinfo.cols.info = string.format("Source Query A2S_REQUEST_CHALLENGE: 0x%02X", resp_type)
        elseif resp_type == 0x55 then
            pinfo.cols.info = string.format("Source Query A2S_PLAYER_REQUEST: 0x%02X", resp_type)
        else
            pinfo.cols.info = string.format("Source Query Type: 0x%02X", resp_type)
        end
    end
end

local udp_port = DissectorTable.get("udp.port")
for i = 27015, 28000 do
    udp_port:add(i, source_proto)
end
