# sndiortp

Play RTP streams or send recorded audio over RTP

## Description

The sndiortp utility can record audio from a sndio(7) audio device and send it
on the network over RTP. Similarly it can receive audio streams over RTP and
play the result on the device.

Only 16-bit or 24-bit PCM payload is supported.

This utility is mainly intended to test RTP capable audio equipment but
it may also be used to broadcast audio over a fast local area network.

## Examples

Send recorded data to 192.168.0.1 port 5120:

	sndiortp rtp://192.168.0.1:5120

Receive RTP streams on port 5120 and play the resulting mix:

	sndiortp -l rtp://:5120

## Installation

The sndiortp utility works on Linux, OpenBSD, and probably other
UNIX-like OSes with the sndio library. To install sndiortp, make sure
sndio is present (ex. libsndio-dev on Debian), then run:

	make && make install

## Feedback

Feedback is welcome. Report any bugs to <alex@caoua.org>.
