using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using Data;
using Data.Actions.Notify;
using Data.Actions.Notify.SoundElements;
using System.Windows.Threading;

namespace DamageMeter.UI
{
    public class ActionVM : TSPropertyChanged
    {
        private readonly NotifyAction _action;
        private Balloon _balloon;
        private string _balloonTitle;
        private string _balloonBody;
        private int _balloonDisplayTime;
        private EventType _eventType;
        private bool _hasBalloon;
        private SoundType _soundType;

        public SoundType SoundType
        {
            get => _soundType;
            set
            {
                if (_soundType == value) return;
                _soundType = value;
                _action.Sound = _soundType switch
                {
                    SoundType.Music => new Music("", 1, 1000),
                    SoundType.Beeps => new Beeps(new List<Beep> { new(250, 500), new(0, 250), new(250, 500) }),
                    SoundType.TTS => new TextToSpeech("", VoiceGender.Neutral, VoiceAge.Adult, 0, BasicTeraData.Instance.WindowData.UILanguage, 100, 0),
                    _ => null
                };
                SoundData = CreateSoundData(_action.Sound);
                NotifyPropertyChanged();
                NotifySearchChanged();
            }
        }

        public string DeliverySummary
        {
            get
            {
                var notification = HasBalloon ? "Notification" : "No notification";
                var sound = SoundType == SoundType.None ? "No sound" : SoundType.ToString();
                return $"{notification} / {sound}";
            }
        }

        public string SearchText => string.Join(" ", new[]
        {
            HasBalloon ? "notification balloon popup toast" : "no notification",
            BalloonTitle,
            BalloonText,
            BalloonDisplayTime.ToString(CultureInfo.InvariantCulture),
            EventType.ToString(),
            SoundType.ToString(),
            SoundData switch
            {
                TtsDataVM tts => $"tts text to speech {tts.Text} {tts.Gender} {tts.Age} {tts.Culture} {tts.Volume} {tts.Rate}",
                MusicDataVM music => $"music {music.File} {music.Volume} {music.Duration}",
                BeepsDataVM beeps => $"beep beeps {beeps.Beeps.Count}",
                _ => string.Empty
            }
        });

        public bool HasBalloon
        {
            get => _hasBalloon;
            set
            {
                if (_hasBalloon == value) return;
                _hasBalloon = value;
                if (value)
                {
                    _balloon ??= new Balloon("", "", 3000, EventType.MissingAb);
                    _action.Balloon = _balloon;
                }
                else
                {
                    _action.Balloon = null;
                }
                if (value)
                {
                    _balloonTitle = _balloon.TitleText;
                    _balloonBody = _balloon.BodyText;
                    _balloonDisplayTime = _balloon.DisplayTime;
                    _eventType = _balloon.EventType;
                    NotifyPropertyChanged(nameof(BalloonTitle));
                    NotifyPropertyChanged(nameof(BalloonText));
                    NotifyPropertyChanged(nameof(BalloonDisplayTime));
                    NotifyPropertyChanged(nameof(EventType));
                }
                NotifyPropertyChanged();
                NotifySearchChanged();
            }
        }

        public string BalloonTitle
        {
            get => _balloonTitle;
            set
            {
                if (_balloonTitle == value) return;
                _balloonTitle = value;
                if (_balloon != null) _balloon.TitleText = value;
                NotifyPropertyChanged();
                NotifySearchChanged();
            }
        }

        public string BalloonText
        {
            get => _balloonBody;
            set
            {
                if (_balloonBody == value) return;
                _balloonBody = value;
                if (_balloon != null) _balloon.BodyText = value;
                NotifyPropertyChanged();
                NotifySearchChanged();
            }
        }

        public int BalloonDisplayTime
        {
            get => _balloonDisplayTime;
            set
            {
                if (_balloonDisplayTime == value) return;
                _balloonDisplayTime = value;
                if (_balloon != null) _balloon.DisplayTime = value;
                NotifyPropertyChanged();
                NotifySearchChanged();
            }
        }

        public EventType EventType
        {
            get => _eventType;
            set
            {
                if (_eventType == value) return;
                _eventType = value;
                if (_balloon != null) _balloon.EventType = value;
                NotifyPropertyChanged();
                NotifySearchChanged();
            }
        }

        private BaseSoundVM _soundData;

        public BaseSoundVM SoundData
        {
            get => _soundData;
            set
            {
                if (_soundData == value) return;
                if (_soundData != null) _soundData.PropertyChanged -= OnSoundDataPropertyChanged;
                _soundData = value;
                if (_soundData != null) _soundData.PropertyChanged += OnSoundDataPropertyChanged;
                NotifyPropertyChanged();
                NotifySearchChanged();
            }
        }

        public ActionVM(NotifyAction action) : base(Dispatcher.CurrentDispatcher)
        {
            _action = action;
            _balloon = action.Balloon;

            if (_balloon != null)
            {
                _hasBalloon = true;

                _balloonTitle = _balloon.TitleText;
                _balloonBody = _balloon.BodyText;

                _balloonDisplayTime = _balloon.DisplayTime;

                _eventType = _balloon.EventType;
            }

            if (action.Sound != null)
            {
                _soundType = action.Sound switch
                {
                    Music => SoundType.Music,
                    Beeps => SoundType.Beeps,
                    TextToSpeech => SoundType.TTS,
                    _ => SoundType.None
                };

                SoundData = CreateSoundData(action.Sound);
            }
        }

        private static BaseSoundVM CreateSoundData(SoundInterface sound)
        {
            return sound switch
            {
                Music m => new MusicDataVM(m),
                Beeps b => new BeepsDataVM(b),
                TextToSpeech tts => new TtsDataVM(tts),
                _ => null
            };
        }

        private void OnSoundDataPropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            NotifySearchChanged();
        }

        private void NotifySearchChanged()
        {
            NotifyPropertyChanged(nameof(DeliverySummary));
            NotifyPropertyChanged(nameof(SearchText));
        }
    }
}
