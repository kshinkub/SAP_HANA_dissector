-- This is Wireshark dissector for SAP HANA.
-- @auther Koji Shinkubo <kshinkub@gmail.com>
-- How to use
-- 1. Put this file(saphana.lua) into the following directory
--   macOS: /Applications/Wireshark.app/Contents/Resources/share/wireshark
--   Windows: C:\Program Files\Wireshark
-- 2. Modify init.lua 
--     mod: disable_lua = true => false
--     add: dofile(DATA_DIR.."saphana.lua")
--
do
    local msgHeaderSize  = 32
    local segHeaderSize  = 24
    local partHeaderSize = 16 
    local noofparts

    -- Protocol definition
    local p_saphana = Proto("HANA", "SAP HANA SQL Command Network Protocol")

    -- Definition for BOOLEAN
    local bool        = {[0] = "FALSE", [1] = "TRUE"}

    -- Definition for data type
    local dataTypeName= {
                        [0] = "NULL",
                        [1] = "TINYINT",
                        [2] = "SMALLINT",
                        [3] = "INT",
                        [4] = "BIGINT",
                        [5] = "DECIMAL",
                        [6] = "REAL",
                        [7] = "DOUBLE",
                        [8] = "CHAR",
                        [9] = "VARCHAR",
                        [10]= "NCHAR",
                        [11]= "NVARCHAR",
                        [12]= "BINARY",
                        [13]= "VARBINARY",
                        [14]= "DATE (deprecated type)",
                        [15]= "TIME (deprecated type)",
                        [16]= "TIMESTAMP",
                        [17]= "TIME_TZ",
                        [18]= "TIME_LTZ",
                        [19]= "TIMESTAMP_TZ",
                        [20]= "TIMESTAMP_LTZ",
                        [21]= "INTERVAL_YM",
                        [22]= "INTERVAL_DS",
                        [23]= "ROWID",
                        [24]= "UROWID",
                        [25]= "CLOB",
                        [26]= "NCLOB",
                        [27]= "BLOB",
                        [28]= "BOOLEAN",
                        [29]= "STRING",
                        [30]= "NSTRING",
                        [31]= "BLOCATOR",
                        [32]= "NLOCATOR",
                        [33]= "BSTRING",
                        [34]= "DECIMAL_DIGIT_ARRAY",
                        [35]= "VARCHAR2",
                        [36]= "VARCHAR3",
                        [37]= "NVARCHAR3",
                        [38]= "VARBINARY3",
                        [39]= "VARGROUP",
                        [40]= "TINYINT_NOTNULL",
                        [41]= "SMALLINT_NOTNULL",
                        [42]= "INT_NOTNULL",
                        [43]= "BIGINT_NOTNULL",
                        [44]= "ARGUMENT",
                        [45]= "TABLE",
                        [46]= "CURSOR",
                        [47]= "SMALLDECIMAL",
                        [48]= "ABAPITAB",
                        [49]= "ABAPSTRUCT",
                        [50]= "ARRAY",
                        [51]= "TEXT",
                        [52]= "SHORTTEXT",
                        [53]= "FIXEDSTRING",
                        [54]= "FIXEDPOINTDECIMAL",
                        [55]= "ALPHANUM",
                        [56]= "TLOCATOR",
                        [61]= "LONGDATE",
                        [62]= "SECONDDATE",
                        [63]= "DAYDATE",
                        [64]= "SECONDTIME",
                        [65]= "CSDATE",
                        [66]= "CSTIME",
                        [71]= "BLOB_DISK",
                        [72]= "CLOB_DISK",
                        [73]= "NCLOB_DISK",
                        [74]= "GEOMETRY",
                        [75]= "POINT",
                        [76]= "FIXED16",
                        [77]= "BLOB_HYBRID",
                        [78]= "CLOB_HYBRID",
                        [79]= "NCLOB_HYBRID",
                        [80]= "POINTZ"}

    -- Definition for segment kind in segment header
    local segKindName = {[0] = "Invalid",
                         [1] = "Request",
                         [2] = "Reply",
                         [5] = "Error"}

    -- Definition for message type in segment header
    local msgTypeName = {[0] = "NIL",
                         [2] = "EXECUTEDIRECT",
                         [3] = "PREPARE",
                         [4] = "ABAPSTREAM",
                         [5] = "XA_START",
                         [6] = "XA_JOIN",
                         [13]= "EXECUTE",
                         [16]= "READLOB",
                         [17]= "WRITELOB",
                         [18]= "FINDLOB",
                         [25]= "PING",
                         [65]= "AUTHENTICATE",
                         [66]= "CONNECT",
                         [67]= "COMMIT",
                         [68]= "ROLLBACK",
                         [69]= "CLOSERESULTSET",
                         [70]= "DROPSTATEMENTID",
                         [71]= "FETCHNEXT",
                         [72]= "FETCHABSOLUTE",
                         [73]= "FETCHRELATIVE",
                         [74]= "FETCHFIRST",
                         [75]= "FETCHLAST",
                         [77]= "DISCONNECT",
                         [78]= "EXECUTEITAB",
                         [79]= "FETCHNEXTITAB",
                         [80]= "INSERTNEXTITAB",
                         [81]= "BATCHPREPARE",
                         [82]= "DBCONNECTINFO"}

    -- Definition for part kind in part header
    local partKindName = {[0] = "NIL",
                          [3] = "COMMAND",
                          [5] = "RESULTSET",
                          [6] = "ERROR",
                          [10]= "STATEMENTID",
                          [11]= "TRANSACTIONID",
                          [12]= "ROWSAFFECTED",
                          [13]= "RESULTSETID",
                          [15]= "TOPOLOGYINFORMATION",
                          [16]= "TABLELOCATION",
                          [17]= "READLOBREQUEST",
                          [18]= "READLOBREPLY",
                          [25]= "ABAPISTREAM",
                          [26]= "ABAPOSTREAM",
                          [27]= "COMMANDINFO",
                          [28]= "WRITELOBREQUEST",
                          [30]= "WRITELOBREPLY",
                          [32]= "PARAMETERS",
                          [33]= "AUTHENTICATION",
                          [34]= "SESSIONCONTEXT",
                          [39]= "STATEMENTCONTEXT",
                          [40]= "PARTITIONINFORMATION",
                          [41]= "OUTPUTPARAMETERS",
                          [42]= "CONNECTOPTIONS",
                          [43]= "COMMITOPTIONS",
                          [44]= "FETCHOPTIONS",
                          [45]= "FETCHSIZE",
                          [47]= "PARAMETERMETADATA",
                          [48]= "RESULTSETMETADATA",
                          [49]= "FINDLOBREQUEST",
                          [50]= "FINDLOBREPLY",
                          [51]= "ITABSHM",
                          [53]= "ITABCHUNKMETADATA",
                          [55]= "ITABMETADATA",
                          [56]= "ITABRESULTCHUNK",
                          [57]= "CLIENTINFO",
                          [58]= "STREAMDATA",
                          [59]= "OSTREAMRESULT",
                          [60]= "FDAREQUESTMETADATA",
                          [61]= "FDAREPLYMETADATA",
                          [62]= "BATCHPREPARE",
                          [63]= "BATCHEXECUTE",
                          [64]= "TRANSACTIONFLAGS",
                          [65]= "ROWDATAPARTMETADATA",
                          [66]= "COLDATAPARTMETADATA",
                          [67]= "DBCONNECTINFO",
                          [68]= "LOBFLAGS",
                          [69]= "RESULTSETOPTIONS",
                          [70]= "XATRANSACTIONINFO"}

    -- Definition for part attribute in part header
    local partAttrName = {[0] = "LASTPACKET",
                          [1] = "NEXTPACKET",
                          [2] = "FIRSTPACKET",
                          [3] = "ROWNOTFOUND",
                          [4] = "RESULTSETCLOSED",
                          [5] = "RESERVED5",
                          [6] = "RESERVED6",
                          [7] = "RESERVED7"}

    -- Definition for debug
    local f_debug_uint8   = ProtoField.uint8 ("HANA.debug_uint8"  , "Debug UINT8" )

    -- Definition for message header fields
    local f_messageHeader = ProtoField.none  ("HANA.messageHeader", "Message Header" )
    local f_sessionid     = ProtoField.int64 ("HANA.sessionid"    , "Session Identifier" )
    local f_packetcount   = ProtoField.int32 ("HANA.packetcount"  , "Packet Sequence Number" )
    local f_varpartlength = ProtoField.uint32("HANA.varpartlength", "Packet Length" )
    local f_varpartsize   = ProtoField.uint32("HANA.varpartsize"  , "Packet Size" )
    local f_noofseg       = ProtoField.int16 ("HANA.noofseg"      , "Number of segments" )

    -- Definition for segment header field
    local f_segmentHeader = ProtoField.none  ("HANA.segmentHeader", "Segment Header" )
    local f_segmentlength = ProtoField.int32 ("HANA.segmentlength", "Segment Length" )
    local f_segmentofs    = ProtoField.int32 ("HANA.segmentofs"   , "Segment Offset" )
    local f_noofparts     = ProtoField.int16 ("HANA.noofparts"    , "Number of containded parts" )
    local f_segmentno     = ProtoField.int16 ("HANA.segmentno"    , "Number of segments" )
    local f_segmentkind   = ProtoField.int8  ("HANA.segmentkind"  , "Segment Kind"
                                             , base.DEC, segKindName )
    local f_messeagetype  = ProtoField.int8  ("HAHA.messagetype"  , "Action requested from database server"
                                             , base.DEC, msgTypeName)
    local f_commit        = ProtoField.int8  ("HAHA.commit"       , "Commit command" )
    local f_cmdoptions    = ProtoField.int8  ("HAHA.cmdoptions"   , "Command options" )
    local f_functioncode  = ProtoField.int16 ("HAHA.functioncode" , "Nature of statement or functionality" )

    -- Definition for part header fields
    local f_partHeader    = ProtoField.none  ("HANA.partHeader"   , "Part Header" )
    local f_partkind      = ProtoField.int8  ("HANA.partkind"     , "Nature of part data"
                                             , base.DEC, partKindName )
    local f_partattr      = ProtoField.int8  ("HANA.partattr"     , "Futher attributes of part"
                                             , base.DEC, partAttrName )
    local f_argcount      = ProtoField.int16 ("HANA.argcount"     , "Argument count" )
    local f_bigargcount   = ProtoField.int32 ("HANA.bigargcount"  , "Big argument count" )
    local f_buflen        = ProtoField.int32 ("HANA.buflen"       , "Length of the part buffer in bytes" )
    local f_bufsize       = ProtoField.int32 ("HANA.bufsize"      , "length remaining in the packet" )

    -- Define for part buffer fields
    local f_partBuffer    = ProtoField.none  ("HANA.partBuffer"   , "Part Buffer" )
    local f_partData      = ProtoField.none  ("HANA.partData"     , "Part Data" )
    -- OTHER
    local f_data          = ProtoField.bytes ("HANA.data"         , "Data" )
    -- COMMAND (3)
    local f_command       = ProtoField.string("HANA.command"      , "Command" )
    -- STATEMENTID (10)
    local f_statementid   = ProtoField.int64 ("HANA.statementid"  , "Statement ID" )
    -- RESULTSETID (13)
    local f_resultsetid   = ProtoField.int64 ("HANA.resultsetid"  , "Resultset ID" )
    -- AUTHENTICATION (33)
    local f_auth_value    = ProtoField.string("HANA.auth_value"   , "Value" )
    -- RESULTSETMETADATA (48)
    local f_rsm_columnopt = ProtoField.bytes ("HANA.rsm_columnopt", "Column Options" )
    local f_rsm_datatype  = ProtoField.int8  ("HANA.rsm_datatype" , "Data Type"
                                             , base.DEC, dataTypeName )
    local f_rsm_fraction  = ProtoField.int16 ("HANA.rsm_fraction" , "Scale of the column" )
    local f_rsm_length    = ProtoField.int16 ("HANA.rsm_fraction" , "Length/Precision" )
    local f_rsm_filler    = ProtoField.int16 ("HANA.rsm_filler"   , "Filler" )
    local f_rsm_tabnofs   = ProtoField.uint32("HANA.rsm_tabnofs"  , "Offset of table name" 
                                             , base.HEX )
    local f_rsm_tabname   = ProtoField.string("HANA.rsm_tabname"  , "Table Name")
    local f_rsm_schnofs   = ProtoField.uint32("HANA.rsm_schnofs"  , "Offset of schema name"
                                             , base.HEX )
    local f_rsm_schname   = ProtoField.string("HANA.rsm_schname"  , "Schema Name")
    local f_rsm_colnofs   = ProtoField.uint32("HANA.rsm_colnofs"  , "Offset of column name"
                                             , base.HEX )
    local f_rsm_colname   = ProtoField.string("HANA.rsm_colname"  , "Column Name")
    local f_rsm_coldisnofs= ProtoField.uint32("HANA.rsm_coldisnofs", "Offset of column display name"
                                             , base.HEX )
    local f_rsm_coldisname= ProtoField.string("HANA.rsm_coldisname", "Column Display Name")
    -- CLIENTINFO (57)
    local f_client_value  = ProtoField.string("HANA.client_value" , "Value" )
    -- DBCONNECTINFO (67)
    local f_dbcon_dbname  = ProtoField.string("HANA.dbcon_dbname" , "Database Name" )
    local f_dbcon_host    = ProtoField.string("HANA.dbcon_host"   , "Host Name" )
    local f_dbcon_port    = ProtoField.int8  ("HANA.dbcon_port"   , "Port" )
    local f_dbcon_iscon   = ProtoField.int8  ("HANA.dbcon_iscon"  , "Is Connected"
                                             , base.DEC, bool)

    -- Register fields
    p_saphana.fields = {f_debug_uint8,
                        -- message header
                        f_messageHeader,
                        f_sessionid,f_packetcount,f_varpartlength,f_varpartsize,f_noofseg,
                        -- segment header
                        f_segmentHeader,
                        f_segmentlength,f_segmentofs,f_noofparts,f_segmentno,f_segmentkind,
                        f_messeagetype,f_commit,f_cmdoptions,f_functioncode,
                        -- part header
                        f_partHeader,
                        f_partkind,f_partattr,f_argcount,f_bigargcount,f_buflen,f_bufsize,
                        -- part buffer
                        f_partBuffer,f_partData,
                        f_data,
                        f_command,
                        f_statementid,
                        f_resultsetid,
                        f_auth_value,
                        f_rsm_columnopt,f_rsm_datatype,f_rsm_fraction,f_rsm_length,f_rsm_filler,
                        f_rsm_tabnofs,f_rsm_schnofs,f_rsm_colnofs,f_rsm_coldisnofs,
                        f_rsm_tabname,f_rsm_schname,f_rsm_colname,f_rsm_coldisname,
                        f_client_value,
                        f_dbcon_dbname,f_dbcon_host,f_dbcon_port,f_dbcon_iscon
                       }

    -- COMMAND (3)
    local function decode_3(tree, buf, offset, size)
        tree:add_le(f_command, buf(offset, size))
    end

    -- STATEMENTID (10)
    local function decode_10(tree, buf, offset, size)
        tree:add_le(f_statementid, buf(offset, size))
    end

    -- RESULTSETID (13)
    local function decode_13(tree, buf, offset, size)
        tree:add_le(f_resultsetid, buf(offset, size))
    end

    -- AUTHENTICATION (33)
    local function decode_33(tree, buf, offset, size)
        local partDataTree = tree:add(f_partData)
        local field_cnt = buf(offset, 2):le_int()
        local len_ofs = 0
        local field_len = buf(offset + 2, 1):le_uint()
        local prev_field_len

        if field_len <= 250 then
            len_ofs = 1
        else
            field_len = buf(offset + 2 + 1, 2):le_uint()
            len_ofs = 3
        end

        local int i = 1
        while true do
            partDataTree:add_le (f_auth_value , buf(offset + 2 + len_ofs , field_len))
            if i >= field_cnt then
                break
            end
            prev_field_len = field_len
            field_len = buf(offset + 2 + len_ofs + field_len, 1):le_uint()
            if field_len <= 250 then
                len_ofs = len_ofs + prev_field_len + 1
            else
                field_len = buf(offset + 2 + len_ofs + field_len + 1, 2):le_uint()
                len_ofs = len_ofs + prev_field_len + 3
            end
            i = i + 1
        end
    end

    -- RESULTSETMETADATA (48)
    local function decode_48(tree, argcount, buf, offset, size)
        local fixOffset = 24
        local t_ofs
        local t_len_ofs
        local partDataTree = {}

        for i=0, argcount-1 do
            partDataTree[i+1] = tree:add( f_partData )

            partDataTree[i+1]:add_le(f_rsm_columnopt, buf( offset + (fixOffset * i) , 1))
            partDataTree[i+1]:add_le(f_rsm_datatype , buf( offset + (fixOffset * i) + 1 , 1))
            partDataTree[i+1]:add_le(f_rsm_fraction , buf( offset + (fixOffset * i) + 2 , 2))
            partDataTree[i+1]:add_le(f_rsm_length   , buf( offset + (fixOffset * i) + 4 , 2))

            -- table name
            --partDataTree[i+1]:add_le ( f_rsm_tabnofs   , buf( offset + (fixOffset * i) + 8 , 4 ) )
            t_ofs = buf(offset + (fixOffset * i) + 8, 4):le_int()
            if t_ofs ~= 4294967295 then
                t_len_ofs = offset + (fixOffset * argcount) + t_ofs
                partDataTree[i+1]:add_le(f_rsm_tabname, buf(t_len_ofs + 1, buf(t_len_ofs, 1):le_int()))
            end

            -- schema name
            --partDataTree[i+1]:add_le ( f_rsm_schnofs   , buf( offset + (fixOffset * i) + 12 , 4 ) )
            t_ofs = buf(offset + (fixOffset * i) + 12 , 4):le_int()
            if t_ofs ~= 4294967295 then
                t_len_ofs = offset + (fixOffset * argcount) + t_ofs
                partDataTree[i+1]:add_le(f_rsm_schname, buf(t_len_ofs + 1, buf(t_len_ofs, 1):le_int()))
            end

            -- column name
            --partDataTree[i+1]:add_le ( f_rsm_colnofs   , buf( offset + (fixOffset * i) + 16 , 4 ) )
            t_ofs = buf(offset + (fixOffset * i) + 16 , 4):le_int()
            if t_ofs ~= 4294967295 then
                t_len_ofs = offset + (fixOffset * argcount) + t_ofs
                partDataTree[i+1]:add_le(f_rsm_colname, buf(t_len_ofs + 1, buf(t_len_ofs, 1):le_int()))
            end

            -- column display name
            --partDataTree[i+1]:add_le ( f_rsm_coldisnofs, buf( offset + (fixOffset * i) + 20 , 4 ) )
            t_ofs = buf(offset + (fixOffset * i) + 20 , 4):le_int()
            if t_ofs ~= 4294967295 then
                t_len_ofs = offset + (fixOffset * argcount) + t_ofs
                partDataTree[i+1]:add_le(f_rsm_coldisname, buf(t_len_ofs + 1, buf(t_len_ofs, 1):le_int()))
            end
        end
    end

    -- CLIENTINFO (57)
    local function decode_57(tree, buf, offset, size)
        local partDataTree = tree:add(f_partData)
        local t_size = buf(offset, 1):le_int()
        local t_ofs  = 0
        local t_size_ofs = 1
        if t_size == 246 then
            t_size = buf(offset+1, 2):le_int()
            t_size_ofs = 3
        elseif t_size == 257 then
            t_size = buf(offset+1, 4):le_int()
            t_size_ofs = 5
        end
        local ttl_size = t_size

        while ttl_size <= size do
            partDataTree:add_le (f_client_value, buf(offset + t_ofs + t_size_ofs, t_size))
            t_ofs  = (t_ofs + t_size_ofs) + t_size
            t_size_ofs = 1
            t_size = buf(offset + t_ofs, 1):le_uint()
            if t_size == 246 then
                t_size = buf(offset + t_ofs + 1, 2):le_int()
                t_size_ofs = 3
            elseif t_size == 257 then
                t_size = buf(offset + t_ofs + 1, 4):le_int()
                t_size_ofs = 5
            end
            ttl_size = ttl_size + t_size
        end
    end

    -- DBCONNECTINFO (67)
    local function decode_67(tree, buf, offset, size)
        local partDataTree = tree:add(f_partData)
        local idx = buf(offset, 1):le_int()

        if idx == 1 then
            partDataTree:add_le(f_dbcon_dbname, buf(offset + 4, len))
        elseif idx == 2 then
            local len = buf( offset + 2, 2):le_int()
            partDataTree:add_le(f_dbcon_host, buf(offset + 4, len))
        elseif idx == 3 then
            partDataTree:add_le(f_dbcon_port, buf(offset + 2, size))
        else
            partDataTree:add_le(f_dbcon_iscon, buf(offset + 2, size))
        end
    end

    local function partBuffer(tree, bufType, argcount, buf, offset, size)
        if bufType == 3 then        -- COMMAND
            decode_3(tree, buf, offset, size)
        elseif bufType == 10 then   -- STATEMENTID
            decode_10(tree, buf, offset, size)
        elseif bufType == 13 then   -- RESULTSETID
            decode_13(tree, buf, offset, size)
        elseif bufType == 33 then   -- AUTHENTICATION
            decode_33(tree, buf, offset, size)
        elseif bufType == 48 then   -- RESULTSETMETADATA
            decode_48(tree, argcount, buf, offset, size)
        elseif bufType == 57 then   -- CLIENTINFO
            decode_57(tree, buf, offset, size)
        elseif bufType == 67 then   -- DBCONNECTINFO
            decode_67(tree, buf, offset, size)
        else
            tree:add(f_data, buf(offset, size))
        end
    end

    -- Message Header
    local function messageHeader(tree, buf)
        -- Message Header Tree
        local msgHeaderTree = tree:add(f_messageHeader)

        msgHeaderTree:add_le(f_sessionid    , buf(0, 8))
        msgHeaderTree:add_le(f_packetcount  , buf(8, 4))
        msgHeaderTree:add_le(f_varpartlength, buf(12, 4))
        msgHeaderTree:add_le(f_varpartsize  , buf(16, 4))
        msgHeaderTree:add_le(f_noofseg      , buf(20, 2))
    end

    -- Segment Header
    local function segmentHeader(tree, buf)
        -- Segment Header Tree
        local segHeaderTree = tree:add(f_segmentHeader)

        segHeaderTree:add_le(f_segmentlength, buf(msgHeaderSize, 4))
        segHeaderTree:add_le(f_segmentofs   , buf(msgHeaderSize + 4, 4))
        segHeaderTree:add_le(f_noofparts    , buf(msgHeaderSize + 8, 2))
        segHeaderTree:add_le(f_segmentno    , buf(msgHeaderSize + 10, 2))
        segHeaderTree:add_le(f_segmentkind  , buf(msgHeaderSize + 12, 1))

        noofparts = buf(msgHeaderSize + 8, 2):le_int()
        local segmentKind = buf(msgHeaderSize + 12, 1):le_int()
--        if segmentKind ~= 1 then
        if segmentKind == 1 then
            segHeaderTree:add_le(f_messeagetype, buf(msgHeaderSize + 13, 1))
            segHeaderTree:add_le(f_commit      , buf(msgHeaderSize + 14, 1))
            segHeaderTree:add_le(f_cmdoptions  , buf(msgHeaderSize + 15, 1))
            segHeaderTree:add_le(f_functioncode, buf(msgHeaderSize + 16 + 8 + 1, 2))
        end
    end

    -- Segment Header
    local function partHeader(tree, buf)
        -- Part Header Tree
        local partHeaderTree = {}
        local partBufferTree = {}
        local partBufLen = 0
        local t_argcount
        local offset = msgHeaderSize + segHeaderSize + partBufLen

        for i=1, noofparts do
            partHeaderTree[i] = tree:add(f_partHeader)

            partHeaderTree[i]:add_le(f_partkind    ,buf(offset, 1))
            partHeaderTree[i]:add_le(f_partattr    ,buf(offset + 1, 1))
            partHeaderTree[i]:add_le(f_argcount    ,buf(offset + 2, 2))
            partHeaderTree[i]:add_le(f_bigargcount ,buf(offset + 4, 4))
            partHeaderTree[i]:add_le(f_buflen      ,buf(offset + 8, 4))
            partHeaderTree[i]:add_le(f_bufsize     ,buf(offset + 12, 4))

            t_argcount = buf(offset + 2, 2):le_int()

            -- Part Buffer
            local t_partkind = buf(offset, 1):le_int()
            local t_buflen = buf(offset + 8, 4):le_int()
            partBufferTree[i] = partHeaderTree[i]:add(f_partBuffer)
            partBuffer(partBufferTree[i], t_partkind, t_argcount, buf, offset + partHeaderSize, t_buflen)

            -- alignment buffer as 64bit
            partBufLen = math.ceil(t_buflen / 8) * 8

            offset = offset + partHeaderSize + partBufLen
        end
    end

    -- main dissector function
    function p_saphana.dissector ( buf, pkt, root )
        pkt.cols.protocol = "HANA"
        pkt.cols.info:set("SAP HANA SQL Command Network Protocol")
        local hanaTree = root:add(p_saphana, buf())

        hanaTree:append_text(" (" .. buf:len() .. "-byte packet)")

        -- Message Header
        if buf:len() < msgHeaderSize then
            return
        end
        messageHeader(hanaTree, buf)

        -- Segment Header
        if buf:len() < msgHeaderSize + segHeaderSize then
            return
        end
        segmentHeader(hanaTree, buf)

        -- Part Header/Buffer
        partHeader(hanaTree, buf)
    end

    local tcp_encap_table = DissectorTable.get("tcp.port")
    tcp_encap_table:add(39013, p_saphana)
end
