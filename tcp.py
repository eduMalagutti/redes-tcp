import asyncio
from tcputils import *
import random
import os

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, client_seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.server_seq_no = int.from_bytes(os.urandom(2), 'big')
        self.client_seq_no = client_seq_no
        self.ack_no = self.client_seq_no + 1   

        ## Envia o SYN+ACK para o cliente, aceitando a conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        
        flags = FLAGS_SYN | FLAGS_ACK
        
        header = make_header(
            src_port=dst_port, # porta do servidor
            dst_port=src_port, # porta do cliente
            seq_no=self.server_seq_no,
            ack_no=self.ack_no,
            flags=flags,
        )
        header = fix_checksum(header, dst_addr, src_addr) 
        self.servidor.rede.enviar(header, src_addr)
        self.server_seq_no += 1

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida

        # No construtor da classe,
        # um timer pode ser criado assim;
        # self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)

        # é possível cancelar o timer chamando esse método;
        # self.timer.cancel()
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # Verifica se o ACK chegou corretamente (não está duplicado e foi recebido em ordem)
        if seq_no == self.ack_no:
            if self.callback and payload:
                self.callback(self, payload)
            self.ack_no += len(payload)

        if len(payload) > 0 or (flags & (FLAGS_SYN | FLAGS_FIN)):
            header = make_header(
                src_port=dst_port,
                dst_port=src_port,
                seq_no=self.server_seq_no,
                ack_no=self.ack_no,
                flags=FLAGS_ACK
            )
            segmento = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento, src_addr)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        flags = FLAGS_ACK

        # Fragmenta os dados em chunks de tamanho MSS
        for i in range(0, len(dados), MSS):
            chunk = dados[i:i+MSS]  # Pega até MSS bytes

            header = make_header(
                src_port=dst_port,
                dst_port=src_port,
                seq_no=self.server_seq_no,
                ack_no=self.ack_no,
                flags=flags
            )

            segmento = header + chunk
            segmento = fix_checksum(segmento, dst_addr, src_addr)

            self.servidor.rede.enviar(segmento, src_addr)

            # Atualiza o server_seq_no somente pelo tamanho da chunk
            self.server_seq_no += len(chunk)


    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        
        pass
