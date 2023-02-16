import subprocess

commit_str = subprocess.getoutput(
    "cd /home/tina/Documents/catkin_ws/src/blaser_mapping && git log -1"
    " --format=%h\ \%cd --date=local"
)
print("The exit code was: ", commit_str)
