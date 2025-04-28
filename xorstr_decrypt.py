import sys
import ida_allins
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_search
import ida_ua
import idaapi
import idc


class xor_decryption_mod(ida_idaapi.plugmod_t):
    stack_count = 0

    def __del__(self):
        ida_kernwin.msg("unloaded xor decryptor\n")

    def get_insn(self, ea: int):
        """
        Returns the instruction at a linear address
        """
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        return insn

    def get_previous_insn(self, ea):
        """
        Returns the previous instruction
        """
        insn = idaapi.insn_t()
        idaapi.decode_prev_insn(insn, ea)
        return insn

    def get_next_insn(self, previous_insn):
        """
        Returns the next instruction, or None if it can't find any
        """
        insn = idaapi.insn_t()
        if previous_insn.size == 0:
            return None
        idaapi.decode_insn(insn, previous_insn.ea + previous_insn.size)
        return insn

    def find_memory_chunk(self, target_addr, start_ea, chunk_size):
        current_ea = start_ea
        depth = 0
        while current_ea != idaapi.BADADDR and depth < 1000:
            insn = self.get_previous_insn(current_ea)
            if insn is None:
                break

            if insn.itype in [ida_allins.NN_mov]:
                if insn.ops[0].type in [ida_ua.o_mem, ida_ua.o_displ]:
                    if target_addr is None or insn.ops[0].addr == target_addr:
                        if insn.ops[1].type == ida_ua.o_imm:
                            return insn.ops[1].value.to_bytes(chunk_size, sys.byteorder)
                        elif insn.ops[1].type == ida_ua.o_reg:
                            reg_val = self.trace_register_source(insn.ops[1].reg, insn.ea, chunk_size)
                            if reg_val:
                                return reg_val

            depth += 1
            current_ea = insn.ea
        return None

    def byte_xor(self, ba1, ba2):
        """
        Handles a basic xor cipher with two byte arrays
        """
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def find_result_storage_insn(self, start_insn, result_reg):
        current_insn = start_insn
        for _ in range(100):
            next_insn = self.get_next_insn(current_insn)
            if not next_insn:
                return None

            if next_insn.itype in [ida_allins.NN_movdqa, ida_allins.NN_movdqu,
                                   ida_allins.NN_vmovdqa, ida_allins.NN_vmovdqu,
                                   ida_allins.NN_movups] and \
                    next_insn.ops[0].type in [ida_ua.o_mem, ida_ua.o_displ] and \
                    next_insn.ops[1].type == ida_ua.o_reg and \
                    next_insn.ops[1].reg == result_reg:
                return next_insn

            current_insn = next_insn
        return None

    def set_decryption_comment(self, ea, comment):
        idc.set_cmt(ea, comment, 0)
        cfunc = idaapi.decompile(ea)
        if cfunc:
            tl = idaapi.treeloc_t()
            tl.ea = ea
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()

    def process_decryption_result(self, data_source, key_source, func_addr, insn):
        decrypted = self.byte_xor(data_source, key_source)
        comment = 'Decrypted: '
        result = ''
        try:
            result = decrypted.decode('utf-8').rstrip('\x00')
        except:
            result = ' '.join(["{:02x}".format(b) for b in decrypted])
            comment = 'Raw: '

        if len(result) == 0:
            return None

        mov_insn = self.find_result_storage_insn(insn, insn.ops[0].reg)
        if mov_insn:
            self.set_decryption_comment(mov_insn.ea, comment + result)

        return result

    def trace_operand_source(self, start_ea, operand, required_size):
        if operand.type == ida_ua.o_reg:
            return self.trace_register_source(operand.reg, start_ea, required_size)
        elif operand.type in [ida_ua.o_mem, ida_ua.o_displ]:
            return self.trace_memory_source(operand.addr, start_ea, required_size)
        return None

    def trace_register_source(self, reg, start_ea, required_size):
        # print(f"trace_register_source  start {hex(start_ea)}")

        current_ea = start_ea
        depth = 0
        while current_ea != idaapi.BADADDR and depth < 1000:
            insn = self.get_previous_insn(current_ea)
            if insn is None:
                break

            if insn.itype in [ida_allins.NN_vmovdqu, ida_allins.NN_vmovdqa,
                              ida_allins.NN_movups, ida_allins.NN_movdqa]:
                if insn.ops[0].type == ida_ua.o_reg and insn.ops[0].reg == reg:
                    if insn.ops[1].type in [ida_ua.o_mem, ida_ua.o_displ]:
                        return self.trace_memory_source(insn.ops[1].addr, insn.ea, required_size)
                    elif insn.ops[1].type == ida_ua.o_reg:
                        reg = insn.ops[1].reg
                        current_ea = insn.ea
                        continue

            elif insn.itype in [ida_allins.NN_mov]:
                if insn.ops[0].type == ida_ua.o_reg and insn.ops[0].reg == reg:
                    if insn.ops[1].type == ida_ua.o_imm:
                        return insn.ops[1].value.to_bytes(8, sys.byteorder)
                    elif insn.ops[1].type in [ida_ua.o_mem, ida_ua.o_displ]:
                        return self.trace_memory_source(insn.ops[1].addr, insn.ea, required_size)
                    elif insn.ops[1].type == ida_ua.o_reg:
                        reg = insn.ops[1].reg
                        current_ea = insn.ea
                        continue

            depth += 1
            current_ea = insn.ea
        return None

    def trace_memory_source(self, base_addr, start_ea, required_size):
        # print(f"trace_memory_source start {hex(start_ea)}")

        INSN_SIZE_MAP = {
            ida_allins.NN_mov: 8,
            ida_allins.NN_movups: 16,
            ida_allins.NN_vmovdqa: 32,
            ida_allins.NN_vmovdqu: 32
        }

        data = bytearray()
        vector_insns = []
        collected_bytes = 0

        # 第一阶段：收集所有相关的向量存储指令
        current_ea = start_ea
        while current_ea != idaapi.BADADDR and collected_bytes < required_size:
            insn = self.get_previous_insn(current_ea)
            if insn is None:
                break

            if insn.itype in [ida_allins.NN_mov, ida_allins.NN_movups, ida_allins.NN_vmovdqa, ida_allins.NN_vmovdqu]:
                if insn.ops[0].type in [ida_ua.o_mem, ida_ua.o_displ]:
                    insn_addr = insn.ops[0].addr
                    insn_size = INSN_SIZE_MAP[insn.itype]

                    if base_addr is not None and base_addr <= insn.ops[0].addr < base_addr + required_size:
                        vector_insns.append(insn)

                        collected_bytes += insn_size
                        if collected_bytes >= required_size:
                            break

            current_ea = insn.ea

        # 第二阶段：按地址排序并处理指令
        if vector_insns:
            vector_insns.sort(key=lambda x: x.ops[0].addr)
            for insn in vector_insns:
                insn_size = INSN_SIZE_MAP.get(insn.itype, 0)
                src_data = self.trace_register_source(insn.ops[1].reg, insn.ea, insn_size)
                if src_data:
                    data.extend(src_data)

            if len(data) == required_size:
                return bytes(data)

        # 处理通过单独mov指令初始化内存的情况
        data = bytearray()
        chunk_size = 8  # 每个mov处理8字节

        for offset in range(0, required_size, chunk_size):
            target_addr = base_addr + offset if base_addr is not None else None
            chunk_data = self.find_memory_chunk(target_addr, start_ea, chunk_size)
            if not chunk_data:
                return None
            data.extend(chunk_data)

        return bytes(data) if len(data) == required_size else None

    def handle_pxor(self, func_addr):
        """
        Starts the routine for a PXOR instruction
        ex : pxor xmm0, [rbp+1F30h+var_1B90]
        """
        insn = self.get_insn(func_addr)

        data_source = self.trace_operand_source(insn.ea, insn.ops[0], 16)  # xmm总是16字节
        # print(f"get data_source {data_source.hex()}")
        if not data_source or len(data_source) != 16:
            return None

        key_source = self.trace_operand_source(insn.ea, insn.ops[1], 16)
        # print(f"get key_source {key_source.hex()}")
        if not key_source or len(key_source) != 16:
            return None

        return self.process_decryption_result(data_source, key_source, func_addr, insn)

    def handle_vpxor(self, func_addr):
        """
        Starts the routine for a VPXOR instruction
        ex : vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
        """
        insn = self.get_insn(func_addr)

        reg_name = idaapi.get_reg_name(insn.ops[1].reg, 16)
        required_size = 32 if 'ymm' in reg_name else 16

        data_source = self.trace_operand_source(insn.ea, insn.ops[1], required_size)
        # print(f"get data_source {data_source.hex()}")
        if not data_source or len(data_source) != required_size:
            return None

        key_source = self.trace_operand_source(insn.ea, insn.ops[2], required_size)
        # print(f"get key_source {key_source.hex()}")
        if not key_source or len(key_source) != required_size:
            return None

        return self.process_decryption_result(data_source, key_source, func_addr, insn)

    def analyze(self, func_addr):
        """
        calls the right routine depending on the instruction type
        """
        # if func_addr != 0x18000673a:
        #     return None
        insn = self.get_insn(func_addr)
        if insn.itype == ida_allins.NN_vpxor:
            return self.handle_vpxor(func_addr)
        if insn.itype in [ida_allins.NN_pxor, ida_allins.NN_xorps]:
            return self.handle_pxor(func_addr)
        return None

    def analyze_sig_75(self, sig):
        """
        Analyzes all instances of an IDA Pattern with compability for IDA 7.5 (7.5 doesn't have compiled_binpat_vec_t, find_binary is deprecated in IDA 8)
        """
        match_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        while True:
            match_ea = ida_search.find_binary(
                match_ea + 1, ida_idaapi.BADADDR, sig, 16, idc.SEARCH_DOWN)
            if match_ea != idaapi.BADADDR:
                result = self.analyze(match_ea)
                if result != None:
                    print("Found match at {:08X} {}".format(match_ea, result))
            else:
                break

    def analyze_sig(self, sig):
        """
        Analyzes all instances of an IDA Pattern
        """
        match_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        binpat = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(binpat, match_ea, sig, 16)
        while True:
            match_ea = ida_bytes.bin_search(
                match_ea + 1, idaapi.BADADDR, binpat, idaapi.BIN_SEARCH_FORWARD)
            if match_ea != idaapi.BADADDR:
                result = self.analyze(match_ea)
                if result != None:
                    print("Found match at {:08X} {}".format(match_ea, result))
            else:
                break

    def run(self, arg):
        """
        Starts plugin logic
        """
        if idaapi.IDA_SDK_VERSION <= 750:
            self.analyze_sig_75("C5 ? EF")  # vpxor
            self.analyze_sig_75("66 ? EF")  # pxor
            self.analyze_sig_75("0F 57")  # xorps
        else:
            self.analyze_sig("C5 ? EF")  # vpxor
            self.analyze_sig("66 ? EF")  # pxor
            self.analyze_sig("0F 57")  # xorps
        return 0


# This class is instantiated when IDA loads the plugin.
class xor_decryption_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Attempts to detect & decrypt JM Xorstring"
    help = "This is help"
    wanted_name = "Xorstring Decryptor"
    wanted_hotkey = "Alt-F8"

    def init(self):
        ida_kernwin.msg("init() called!\n")
        return xor_decryption_mod()

    def run(self, arg):
        ida_kernwin.msg("ERROR: run() called for global object!\n")
        return 0

    def term(self):
        ida_kernwin.msg("ERROR: term() called (should never be called)\n")


def PLUGIN_ENTRY():
    return xor_decryption_t()
