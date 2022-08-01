# -*- coding: utf-8 -*-

import os
import flask
import requests
import time
from oauth2client.tools import argparser
from datetime import datetime, timedelta
from threading import Thread
from google.cloud import iot_v1
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery


# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"


os.environ["GOOGLE_APPLICATION_CREDENTIALS"]="service_account.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/youtube']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = ''


@app.route('/')
def index():
  return flask.render_template('index.html')

@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  youtube = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)

  response = youtube.liveBroadcasts().list(part="id", broadcastStatus="active").execute()

  # If there is already an active broadcast, show that one.
  # Otherwise, create a new broadcast.

  if len(response['items']) != 0:
    broadcast_id = response['items'][0]['id']
    flask.render_template('video.html', value=broadcast_id)
  else:
    return create_broadcast(youtube)


@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.')
  else:
    return('An error occurred.')


@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>')


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}       


def create_broadcast(youtube):
  args = get_args()
  broadcast_id = insert_broadcast(youtube, args)
  stream_starter = Thread(target= start_stream, args=(youtube, broadcast_id, args,))
  stream_starter.start()
  return flask.render_template('video.html', value=broadcast_id)

def start_stream(youtube, broadcast_id, args):
  (stream_id, STREAM_KEY) = insert_stream(youtube, args)
  bind_broadcast(youtube, broadcast_id, stream_id)
  func_start_rpi_camera_steam(STREAM_KEY)
  func_finish_broadcast_setup(youtube, broadcast_id, stream_id)


def get_args():
  start_time = datetime.utcnow() + timedelta(minutes=1)
  end_time = start_time + timedelta(seconds=180)
  argparser.add_argument("--broadcast-title", help="Broadcast title", default="Webcam")
  argparser.add_argument("--privacy-status", help="Broadcast privacy status", default="public")
  argparser.add_argument("--start-time", help="Scheduled start time", default=str(start_time.isoformat()))
  argparser.add_argument("--end-time", help="Scheduled end time", default=end_time.isoformat())
  argparser.add_argument("--stream-title", help="Stream title", default="New Stream")
  return argparser.parse_args()


# Create a liveBroadcast resource and set its title, scheduled start time,
# scheduled end time, and privacy status.
def insert_broadcast(youtube, options):
  insert_broadcast_response = youtube.liveBroadcasts().insert(
    part="snippet,status",
    body=dict(
      snippet=dict(
        title=options.broadcast_title,
        scheduledStartTime=options.start_time,
        scheduledEndTime=options.end_time
      ),
      status=dict(
        privacyStatus=options.privacy_status,
        selfDeclaredMadeForKids = "true",
        streamStatus="active"
      )
    )
  ).execute()

  return insert_broadcast_response["id"]


# Create a liveStream resource and set its title, format, and ingestion type.
# This resource describes the content that you are transmitting to YouTube.
def insert_stream(youtube, options):
  insert_stream_response = youtube.liveStreams().insert(
    part="snippet,cdn",
    body=dict(
      snippet=dict(
        title=options.stream_title
      ),
      cdn=dict(
        format="1080p",
        ingestionType="rtmp",
        resolution = "720p",
        frameRate = "30fps",

      )
    )
  ).execute()

  dictIngestionInfo = insert_stream_response['cdn']['ingestionInfo']
  streamKey = dictIngestionInfo['streamName']
  return (insert_stream_response["id"],streamKey)


# Bind the broadcast to the video stream. By doing so, you link the video that
# you will transmit to YouTube to the broadcast that the video is for.
def bind_broadcast(youtube, broadcast_id, stream_id):
  youtube.liveBroadcasts().bind(
    part="id,contentDetails",
    id=broadcast_id,
    streamId=stream_id
  ).execute()


def func_finish_broadcast_setup(YOUTUBE_OBJECT, broadcast_id, stream_id):
  sStatus = get_stream_status(YOUTUBE_OBJECT, stream_id)
  while (sStatus != "active"):
      time.sleep(1)
      sStatus = get_stream_status(YOUTUBE_OBJECT, stream_id)
  YOUTUBE_OBJECT.liveBroadcasts().transition(broadcastStatus="testing",id=broadcast_id,part="status").execute()
  bStatus = get_broadcast_status(YOUTUBE_OBJECT, broadcast_id)
  while (bStatus != "testing"):
    time.sleep(1)
    bStatus = get_broadcast_status(YOUTUBE_OBJECT, broadcast_id)
  YOUTUBE_OBJECT.liveBroadcasts().transition(broadcastStatus="live",id=broadcast_id,part="status").execute()
  bStatus = get_broadcast_status(YOUTUBE_OBJECT, broadcast_id)
  while (bStatus != "live"):
    time.sleep(1)
    bStatus = get_broadcast_status(YOUTUBE_OBJECT, broadcast_id)
  sStatus = get_stream_status(YOUTUBE_OBJECT, stream_id)
  while(sStatus == "active"):
      time.sleep(1)
      sStatus = get_stream_status(YOUTUBE_OBJECT, stream_id)
  YOUTUBE_OBJECT.liveBroadcasts().transition(broadcastStatus="complete",id=broadcast_id,part="status").execute()
  bStatus = get_broadcast_status(YOUTUBE_OBJECT, broadcast_id)
  while (bStatus != "complete"):
      time.sleep(1)
      bStatus = get_broadcast_status(YOUTUBE_OBJECT, broadcast_id)


def func_start_rpi_camera_steam(STREAM_KEY):
  service_account_json = ""
  project_id = "Replace with Google Project ID"
  cloud_region = "Replace with cloud region"
  registry_id = "Replace with registry id"
  device_id = "Replace with device id"
  command = STREAM_KEY

  send_command(service_account_json, project_id, cloud_region, registry_id, device_id, command)


def get_broadcast_status(YOUTUBE_OBJECT, broadcast_id):
  response = YOUTUBE_OBJECT.liveBroadcasts().list(id=broadcast_id,part="status").execute()
  return response["items"][0]["status"]["lifeCycleStatus"]


def get_stream_status(YOUTUBE_OBJECT, stream_id):
    liveStream = YOUTUBE_OBJECT.liveStreams().list(part="status", id=stream_id).execute()
    return liveStream['items'][0]['status']['streamStatus']


def send_command(
    service_account_json, project_id, cloud_region, registry_id, device_id, command
):
    """Send a command to a device."""
    # [START iot_send_command]
    print("Sending command to device")
    client = iot_v1.DeviceManagerClient()
    device_path = client.device_path(project_id, cloud_region, registry_id, device_id)
    data = command.encode("utf-8")

    return client.send_command_to_device(
        request={"name": device_path, "binary_data": data}
    )


if __name__ == '__main__':

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run()

