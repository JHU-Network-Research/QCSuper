-- QCSuper GSMTAP extension dissector (QCSuper companion script)
--
-- The GSMTAP v2 ARFCN field is 14 bits wide, so channel numbers above 16383
-- (e.g. EARFCNs of LTE bands 33 and up) can't be stored in it. QCSuper then
-- leaves that field to zero and appends one extra 32-bit header word holding
-- the full channel number (header length = 5 words). Wireshark's GSMTAP
-- dissector skips this word.
--
-- For LTE RRC packets QCSuper also records the serving cell's physical cell
-- ID (it comes from the diag log header, not from the RRC message). The
-- extension is then two words, [full ARFCN][physical cell ID] (header
-- length = 6 words).
--
-- This postdissector exposes:
--   qcsuper.gsmtap_ext.arfcn  for every GSMTAP packet: the extension word
--                             when present, the regular GSMTAP ARFCN
--                             otherwise (marked as generated in that case)
--   qcsuper.gsmtap_ext.pci    when the packet carries a physical cell ID

local gsmtap_ext = Proto('qcsuper.gsmtap_ext', 'QCSuper GSMTAP extension')

local f_arfcn = ProtoField.uint32('qcsuper.gsmtap_ext.arfcn', 'Full ARFCN', base.DEC)
local f_pci = ProtoField.uint32('qcsuper.gsmtap_ext.pci', 'Physical cell ID', base.DEC)
gsmtap_ext.fields = { f_arfcn, f_pci }

local gsmtap_version = Field.new('gsmtap.version')
local gsmtap_hdr_len = Field.new('gsmtap.hdr_len')
local gsmtap_arfcn = Field.new('gsmtap.arfcn')

function gsmtap_ext.dissector(tvb, pinfo, tree)
    local ver, hdr_len = gsmtap_version(), gsmtap_hdr_len()
    if not ver or not hdr_len then return end

    local hdr_bytes = hdr_len.value
    if hdr_bytes <= 15 then hdr_bytes = hdr_bytes * 4 end -- Displayed in words

    if hdr_bytes >= 20 then
        local subtree = tree:add(gsmtap_ext, tvb(ver.offset + 16, hdr_bytes - 16))
        subtree:add(f_arfcn, tvb(ver.offset + 16, 4))
        if hdr_bytes >= 24 then
            subtree:add(f_pci, tvb(ver.offset + 20, 4))
        end
    else
        local arfcn = gsmtap_arfcn()
        if not arfcn then return end
        tree:add(gsmtap_ext):add(f_arfcn, arfcn.value):set_generated()
    end
end

register_postdissector(gsmtap_ext)
