# Visualizations

This trophy shows you some Scapy visualization tools. Tasks #2 and #3 requires running Scapy either in a graphical environment or in a Jupyter notebook.

## Tasks

### Task #1

- create the packet of your choice
- use `raw()` and `hexdump()` to show the build packet values
- call `show()` and `show2()` on the packet and notice the differences
- call `pdfdump()` or `canvas_dump()`

### Task #2

- use `srloop()` to send 100 packets to `8.8.8.8` and `8.8.4.4`
- call `multiplot()` on the resulting packets list and plot IP id

## Hints

- `pdfdump()` accepts the `filename` argument
