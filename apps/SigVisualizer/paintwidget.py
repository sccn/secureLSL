from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtGui import QPalette, QPainter, QPen
from PyQt5.QtWidgets import QWidget, QMessageBox
import lsl_security_helper  # Adds security methods to pylsl
import pylsl
import math
import copy


CHANNEL_Y_FILL = 0.7  # How much of the per-channel vertical space is filled.  > 1 will overlap the lines.


class DataThread(QThread):
    updateStreamNames = pyqtSignal(list, int)
    sendData = pyqtSignal(list, list, list, list)
    changedStream = pyqtSignal()
    securityMismatch = pyqtSignal(list, bool)  # (stream_names, local_has_security)

    def_stream_parms = {'chunk_idx': 0, 'metadata': {}, 'srate': None, 'chunkSize': None,
                        'downSampling': None, 'downSamplingFactor': None, 'downSamplingBuffer': None,
                        'inlet': None, 'stream_idx': None, 'is_marker': False}

    def __init__(self, parent):
        super().__init__(parent)
        self.chunksPerScreen = 50  # For known sampling rate data, divide the screen into this many segments.
        self.seconds_per_screen = 2  # Number of seconds per sweep
        self.streams = []
        self.stream_params = []
        self.sig_strm_idx = -1

    def handle_stream_expanded(self, name):
        if not self.stream_params:
            return  # No streams available (e.g., security mismatch)
        stream_names = [_['metadata']['name'] for _ in self.stream_params]
        if name in stream_names:
            self.sig_strm_idx = stream_names.index(name)
            self.changedStream.emit()

    def update_streams(self):
        if not self.streams:
            self.streams = pylsl.resolve_streams(wait_time=1.0)

            if not self.streams:
                return  # No streams found

            # Check for security mismatches before creating inlets
            local_security = lsl_security_helper.local_security_enabled()
            mismatch_streams = []
            for stream in self.streams:
                stream_secure = stream.security_enabled()
                if stream_secure != local_security:
                    suffix = " (insecure)" if not stream_secure else ""
                    mismatch_streams.append(stream.name() + suffix)

            # Build metadata for all streams (to show in UI)
            all_metadata = []
            for stream in self.streams:
                all_metadata.append({
                    "name": stream.name(),
                    "ch_count": stream.channel_count(),
                    "ch_format": stream.channel_format(),
                    "srate": stream.nominal_srate(),
                    "security_enabled": stream.security_enabled(),
                    "security_fingerprint": stream.security_fingerprint()
                })

            # Always emit stream names to show in UI (even if mismatched)
            self.updateStreamNames.emit(all_metadata, 0 if all_metadata else -1)

            if mismatch_streams:
                self.securityMismatch.emit(mismatch_streams, local_security)
                self.streams = []  # Clear so user can retry with Update button
                return  # Don't create inlets for mismatched streams

            for k, stream in enumerate(self.streams):
                n = stream.name()
                stream_params = copy.deepcopy(self.def_stream_parms)
                stream_params['metadata'].update({
                    "name": n,
                    "ch_count": stream.channel_count(),
                    "ch_format": stream.channel_format(),
                    "srate": stream.nominal_srate(),
                    "security_enabled": stream.security_enabled(),
                    "security_fingerprint": stream.security_fingerprint()
                })
                # ch = stream.desc().child("channels").child("channel")
                # for ch_ix in range(stream.channel_count()):
                #     print("  " + ch.child_value("label"))
                #     ch = ch.next_sibling()

                stream_params['inlet'] = pylsl.StreamInlet(stream)
                stream_params['is_marker'] = stream.channel_format() in ["String", pylsl.cf_string]\
                                             and stream.nominal_srate() == pylsl.IRREGULAR_RATE
                if not stream_params['is_marker']:
                    if self.sig_strm_idx < 0:
                        self.sig_strm_idx = k
                    srate = stream.nominal_srate()
                    stream_params['downSampling'] = srate > 1000
                    stream_params['chunkSize'] = round(srate / self.chunksPerScreen * self.seconds_per_screen)
                    if stream_params['downSampling']:
                        stream_params['downSamplingFactor'] = round(srate / 1000)
                        n_buff = round(stream_params['chunkSize'] / stream_params['downSamplingFactor'])
                        stream_params['downSamplingBuffer'] = [[0] * int(stream.channel_count())] * n_buff
                self.stream_params.append(stream_params)

            self.start()

    def run(self):
        if self.streams:
            while True:
                send_ts, send_data = [], []
                if self.sig_strm_idx >= 0:
                    params = self.stream_params[self.sig_strm_idx]
                    inlet = params['inlet']
                    pull_kwargs = {'timeout': 1}
                    if params['chunkSize']:
                        pull_kwargs['max_samples'] = params['chunkSize']
                    send_data, send_ts = inlet.pull_chunk(**pull_kwargs)
                    if send_ts and params['downSampling']:
                        for m in range(round(params['chunkSize'] / params['downSamplingFactor'])):
                            end_idx = min((m + 1) * params['downSamplingFactor'], len(send_data))
                            for ch_idx in range(int(self.streams[self.sig_strm_idx].channel_count())):
                                buf = [send_data[n][ch_idx] for n in range(m * params['downSamplingFactor'], end_idx)]
                                params['downSamplingBuffer'][m][ch_idx] = sum(buf) / len(buf)
                        send_data = params['downSamplingBuffer']
                send_mrk_ts, send_mrk_data = [], []
                is_marker = [_['is_marker'] for _ in self.stream_params]
                if any(is_marker):
                    for stream_ix, params in enumerate(self.stream_params):
                        if is_marker[stream_ix]:
                            d, ts = params['inlet'].pull_chunk()
                            send_mrk_data.extend(d)
                            send_mrk_ts.extend(ts)

                if any([send_ts, send_mrk_ts]):
                    self.sendData.emit(send_ts, send_data, send_mrk_ts, send_mrk_data)


class PaintWidget(QWidget):

    def __init__(self, widget):
        super().__init__()
        self.reset()
        pal = QPalette()
        pal.setColor(QPalette.Background, Qt.white)
        self.setAutoFillBackground(True)
        self.setPalette(pal)

        self.dataTr = DataThread(self)
        self.dataTr.sendData.connect(self.get_data)
        self.dataTr.changedStream.connect(self.reset)
        self.dataTr.securityMismatch.connect(self.show_security_mismatch)

    def show_security_mismatch(self, stream_names, local_has_security):
        """Show a dialog when there's a security mismatch between streams and local config."""
        stream_list = "<br>".join(
            f"&nbsp;&nbsp;&bull; <span style='color: #0066cc;'>{name}</span>"
            for name in stream_names
        )

        if not local_has_security:
            error_msg = (
                "The following streams require security, but SigVisualizer does not have "
                "security credentials configured:<br><br>" + stream_list +
                "<br><br>To fix this:<br>"
                "&nbsp;&nbsp;1. Run 'lsl-keygen' to generate credentials, or<br>"
                "&nbsp;&nbsp;2. Import shared credentials from an authorized device<br><br>"
                "<span style='color: red; font-weight: bold;'>Cannot visualize streams with "
                "mismatched security settings.</span>"
            )
        else:
            error_msg = (
                "Security mismatch detected for the following streams:<br><br>" +
                stream_list +
                "<br><br>All devices must have the same security configuration "
                "(either all secure or all insecure).<br><br>"
                "<span style='color: red; font-weight: bold;'>Cannot visualize streams with "
                "mismatched security settings.</span>"
            )

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Security Mismatch")
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(error_msg)
        msg_box.exec_()

    def reset(self):
        self.chunk_idx = 0
        self.channelHeight = 0
        self.px_per_samp = 0
        self.dataBuffer = None
        self.markerBuffer = None
        self.lastY = []
        self.scaling = []
        self.mean = []
        self.t0 = 0

    def get_data(self, sig_ts, sig_buffer, marker_ts, marker_buffer):
        update_x0 = float(self.width())
        update_width = 0.

        # buffer should have exactly self.dataTr.chunkSize samples or be empty
        if any(sig_ts):
            if not self.mean:
                self.mean = [0 for _ in range(len(sig_buffer[0]))]
                self.scaling = [1 for _ in range(len(sig_buffer[0]))]
            if self.chunk_idx == 0:
                self.t0 = sig_ts[0]
            self.dataBuffer = copy.deepcopy(sig_buffer)
            px_per_chunk = self.width() / self.dataTr.chunksPerScreen
            update_x0 = self.chunk_idx * px_per_chunk
            update_width = px_per_chunk

        if any(marker_ts):
            px_out = []
            ms_out = []
            px_per_sec = self.width() / self.dataTr.seconds_per_screen
            for ts, ms in zip(marker_ts, marker_buffer):
                if any(sig_ts):  # Relative to signal timestamps
                    this_px = update_x0 + (ts - sig_ts[0]) * px_per_sec
                    if 0 <= this_px <= self.width():
                        px_out.append(this_px)
                        ms_out.append(','.join(ms))
                else:
                    # TODO: Check samples vs pixels for both data stream and marker stream.
                    # I think there is some rounding error.
                    
                    if self.t0 <= ts <= (self.t0 + self.dataTr.seconds_per_screen):
                        px_out.append((ts - self.t0) * px_per_sec)
                        ms_out.append(','.join(ms))
            if any(px_out):
                # Sometimes the marker might happen just off screen so we lose it.
                self.markerBuffer = zip(px_out, ms_out)
                update_x0 = min(update_x0, min(px_out))
                update_width = max(update_width, max([_ - update_x0 for _ in px_out]))

        if any(sig_ts) and update_x0 == sig_ts[0]:
            update_x0 -= self.px_per_samp  # Offset to connect with previous sample

        # Repaint only the region of the screen containing this data chunk.
        if update_width > 0:
            self.update(int(update_x0), 0, int(update_width + 1), self.height())

    def paintEvent(self, event):
        painter = QPainter(self)
        if self.dataBuffer is not None:
            painter.setPen(QPen(Qt.blue))

            n_samps = len(self.dataBuffer)
            n_chans = len(self.dataBuffer[0])

            self.channelHeight = self.height() / n_chans
            self.px_per_samp = self.width() / self.dataTr.chunksPerScreen / n_samps

            # ======================================================================================================
            # Calculate Trend and Scaling
            # ======================================================================================================
            if self.chunk_idx == 0 or not self.mean:
                for chan_idx in range(n_chans):
                    samps_for_chan = [frame[chan_idx] for frame in self.dataBuffer]
                    self.mean[chan_idx] = sum(samps_for_chan) / len(samps_for_chan)

                    for m in range(len(samps_for_chan)):
                        samps_for_chan[m] -= self.mean[chan_idx]

                    data_range = (max(samps_for_chan) - min(samps_for_chan) + 0.0000000000001)
                    self.scaling[chan_idx] = self.channelHeight * CHANNEL_Y_FILL / data_range

            # ======================================================================================================
            # Trend Removal and Scaling
            # ======================================================================================================
            for samp_idx in range(n_samps):
                for chan_idx in range(n_chans):
                    self.dataBuffer[samp_idx][chan_idx] -= self.mean[chan_idx]
                    self.dataBuffer[samp_idx][chan_idx] *= self.scaling[chan_idx]

            # ======================================================================================================
            # Plot
            # ======================================================================================================
            px_per_chunk = self.width() / self.dataTr.chunksPerScreen
            x0 = self.chunk_idx * px_per_chunk
            for ch_idx in range(n_chans):
                chan_offset = (ch_idx + 0.5) * self.channelHeight
                if self.lastY:
                    if not math.isnan(self.lastY[ch_idx]) and not math.isnan(self.dataBuffer[0][ch_idx]):
                        painter.drawLine(int(x0 - self.px_per_samp),
                                         int(-self.lastY[ch_idx] + chan_offset),
                                         int(x0),
                                         int(-self.dataBuffer[0][ch_idx] + chan_offset))

                for m in range(n_samps - 1):
                    if not math.isnan(self.dataBuffer[m][ch_idx]) and not math.isnan(self.dataBuffer[m+1][ch_idx]):
                        painter.drawLine(int(x0 + m * self.px_per_samp),
                                         int(-self.dataBuffer[m][ch_idx] + chan_offset),
                                         int(x0 + (m + 1) * self.px_per_samp),
                                         int(-self.dataBuffer[m+1][ch_idx] + chan_offset))

            # Reset for next iteration
            self.chunk_idx = (self.chunk_idx + 1) % self.dataTr.chunksPerScreen  # For next iteration
            self.lastY = self.dataBuffer[-1]
            self.dataBuffer = None

        if self.markerBuffer is not None:
            painter.setPen(QPen(Qt.red))
            for px, mrk in self.markerBuffer:
                painter.drawLine(int(px), 0, int(px), self.height())
                painter.drawText(int(px - 2 * self.px_per_samp), int(0.95 * self.height()), mrk)
            self.markerBuffer = None
